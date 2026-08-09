package xray

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	proxymancommand "github.com/xtls/xray-core/app/proxyman/command"
	statscommand "github.com/xtls/xray-core/app/stats/command"
	xprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	xvless "github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/store"
	risevless "github.com/mirrage11gpt/rmvpn/internal/vless"
)

const inboundTag = "risevpn-vless-ws"

type Manager struct {
	store   *store.Store
	address string
	now     func() time.Time
	mu      sync.Mutex
	blocked map[string]bool
}

func New(database *store.Store, address string) *Manager {
	return &Manager{store: database, address: address, now: time.Now, blocked: map[string]bool{}}
}

func (m *Manager) Run(ctx context.Context) {
	reconcileTicker := time.NewTicker(5 * time.Second)
	usageTicker := time.NewTicker(15 * time.Second)
	defer reconcileTicker.Stop()
	defer usageTicker.Stop()
	if err := m.Reconcile(ctx); err != nil {
		slog.Warn("Xray reconcile failed", "error", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-reconcileTicker.C:
			if err := m.Reconcile(ctx); err != nil {
				slog.Warn("Xray reconcile failed", "error", err)
			}
		case <-usageTicker.C:
			if err := m.CollectUsage(ctx); err != nil {
				slog.Warn("Xray usage collection failed", "error", err)
			}
		}
	}
}

func (m *Manager) Upsert(ctx context.Context, device model.Device) error {
	m.mu.Lock()
	delete(m.blocked, device.ID)
	m.mu.Unlock()
	if !m.allowed(device) {
		return m.remove(ctx, device.ID)
	}
	return m.ensure(ctx, device)
}

func (m *Manager) Revoke(ctx context.Context, deviceID string) error {
	m.mu.Lock()
	m.blocked[deviceID] = true
	m.mu.Unlock()
	return m.remove(ctx, deviceID)
}

func (m *Manager) Kick(ctx context.Context, deviceID string) error {
	return m.Revoke(ctx, deviceID)
}

func (m *Manager) Reconcile(ctx context.Context) error {
	devices, err := m.store.Devices(ctx)
	if err != nil {
		return err
	}
	current, err := m.current(ctx)
	if err != nil {
		return err
	}
	desired := make(map[string]model.Device, len(devices))
	for _, device := range devices {
		if m.allowed(device) && !m.isBlocked(device.ID) {
			desired[device.ID] = device
		}
	}
	for deviceID := range current {
		device, wanted := desired[deviceID]
		if !wanted {
			if err := m.remove(ctx, deviceID); err != nil {
				return err
			}
			continue
		}
		expected, err := risevless.IDFromCredentialHash(device.CredentialHash)
		if err != nil {
			return err
		}
		if current[deviceID] != expected {
			if err := m.remove(ctx, deviceID); err != nil {
				return err
			}
			if err := m.add(ctx, device); err != nil {
				return err
			}
		}
		delete(desired, deviceID)
	}
	for _, device := range desired {
		if err := m.add(ctx, device); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) CollectUsage(ctx context.Context) error {
	devices, err := m.store.Devices(ctx)
	if err != nil {
		return err
	}
	connection, err := m.dial(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	client := statscommand.NewStatsServiceClient(connection)
	for _, device := range devices {
		var uplink, downlink int64
		for direction, target := range map[string]*int64{"uplink": &uplink, "downlink": &downlink} {
			response, err := client.GetStats(ctx, &statscommand.GetStatsRequest{
				Name: "user>>>" + email(device.ID) + ">>>traffic>>>" + direction, Reset_: true,
			})
			if status.Code(err) == codes.NotFound {
				continue
			}
			if err != nil {
				return err
			}
			*target = response.GetStat().GetValue()
		}
		if uplink > 0 || downlink > 0 {
			if _, err := m.store.AddUsage(ctx, device.ID, uplink, downlink, m.now().UTC()); err != nil {
				return err
			}
			updated, found, err := m.store.DeviceByID(ctx, device.ID)
			if err != nil {
				return err
			}
			if found && !m.allowed(updated) {
				_ = m.Revoke(ctx, device.ID)
			}
		}
	}
	return nil
}

func (m *Manager) ensure(ctx context.Context, device model.Device) error {
	current, err := m.current(ctx)
	if err != nil {
		return err
	}
	expected, err := risevless.IDFromCredentialHash(device.CredentialHash)
	if err != nil {
		return err
	}
	if current[device.ID] == expected {
		return nil
	}
	if _, exists := current[device.ID]; exists {
		if err := m.remove(ctx, device.ID); err != nil {
			return err
		}
	}
	return m.add(ctx, device)
}

func (m *Manager) add(ctx context.Context, device model.Device) error {
	id, err := risevless.IDFromCredentialHash(device.CredentialHash)
	if err != nil {
		return err
	}
	connection, err := m.dial(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	operation := &proxymancommand.AddUserOperation{User: &xprotocol.User{
		Email: email(device.ID), Level: 0,
		Account: serial.ToTypedMessage(&xvless.Account{Id: id, Encryption: "none"}),
	}}
	_, err = proxymancommand.NewHandlerServiceClient(connection).AlterInbound(ctx, &proxymancommand.AlterInboundRequest{
		Tag: inboundTag, Operation: serial.ToTypedMessage(operation),
	})
	return err
}

func (m *Manager) remove(ctx context.Context, deviceID string) error {
	connection, err := m.dial(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	operation := &proxymancommand.RemoveUserOperation{Email: email(deviceID)}
	_, err = proxymancommand.NewHandlerServiceClient(connection).AlterInbound(ctx, &proxymancommand.AlterInboundRequest{
		Tag: inboundTag, Operation: serial.ToTypedMessage(operation),
	})
	if status.Code(err) == codes.NotFound || strings.Contains(strings.ToLower(fmt.Sprint(err)), "not found") {
		return nil
	}
	return err
}

func (m *Manager) current(ctx context.Context) (map[string]string, error) {
	connection, err := m.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	response, err := proxymancommand.NewHandlerServiceClient(connection).GetInboundUsers(ctx, &proxymancommand.GetInboundUserRequest{Tag: inboundTag})
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(response.GetUsers()))
	for _, user := range response.GetUsers() {
		deviceID := strings.TrimSuffix(user.GetEmail(), "@risevpn")
		if deviceID == user.GetEmail() || user.GetAccount() == nil {
			continue
		}
		instance, err := user.GetAccount().GetInstance()
		if err != nil {
			continue
		}
		account, ok := instance.(*xvless.Account)
		if ok {
			result[deviceID] = account.GetId()
		}
	}
	return result, nil
}

func (m *Manager) dial(ctx context.Context) (*grpc.ClientConn, error) {
	if m.address == "" {
		return nil, errors.New("Xray API address is missing")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return grpc.DialContext(dialCtx, m.address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
}

func (m *Manager) allowed(device model.Device) bool {
	now := m.now().UTC()
	if !device.Active || !device.SubscriptionEnds.After(now) {
		return false
	}
	policy, ok := device.Plan.Policy()
	if !ok {
		return false
	}
	quota := device.QuotaBytes
	if quota <= 0 {
		quota = policy.QuotaBytes
	}
	exhausted := device.UsedBytes >= quota
	if device.Plan == model.Trial && exhausted {
		return false
	}
	return exhausted || device.LeaseBytes <= 0 || (device.LeaseExpires.After(now) && device.UsedBytes < device.LeaseBytes)
}

func (m *Manager) isBlocked(deviceID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blocked[deviceID]
}

func email(deviceID string) string { return deviceID + "@risevpn" }
