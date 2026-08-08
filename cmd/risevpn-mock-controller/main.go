package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/mirrage11gpt/rmvpn/internal/compliance"
	"github.com/mirrage11gpt/rmvpn/internal/enrollment"
	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/security"
)

type controller struct {
	caCert     *x509.Certificate
	caKey      ed25519.PrivateKey
	caPEM      string
	serverCert tls.Certificate
	plan       model.Plan
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	bundleText := flag.String("bundle", "", "rvpn1_ enrollment bundle")
	listen := flag.String("listen", ":9443", "mTLS WebSocket listen address")
	publicURL := flag.String("public-url", "wss://127.0.0.1:9443/v1/nodes/connect", "URL reachable by the node")
	claimOverride := flag.String("claim-url", "", "override claim endpoint from bundle")
	planName := flag.String("plan", "PLUS", "test device plan")
	flag.Parse()
	if *bundleText == "" {
		return errors.New("--bundle is required")
	}
	bundle, err := decodeBundle(*bundleText)
	if err != nil {
		return err
	}
	plan := model.Plan(strings.ToUpper(*planName))
	if _, ok := plan.Policy(); !ok {
		return errors.New("invalid plan")
	}
	public, err := security.Decode(bundle.NodePublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("bundle has invalid node public key")
	}
	parsedURL, err := url.Parse(*publicURL)
	if err != nil || parsedURL.Scheme != "wss" {
		return errors.New("--public-url must be wss://")
	}
	c, err := newController(parsedURL.Hostname(), plan)
	if err != nil {
		return err
	}
	nodeCertificate, err := c.issueNodeCertificate(ed25519.PublicKey(public), bundle.NodeID)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	roots.AddCert(c.caCert)
	server := &http.Server{Addr: *listen, Handler: c.handler(), ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.serverCert},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}}
	listener, err := tls.Listen("tcp", *listen, server.TLSConfig)
	if err != nil {
		return err
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server: %v", err)
		}
	}()

	claimURL := bundle.ClaimEndpoint
	if *claimOverride != "" {
		claimURL = *claimOverride
	}
	claim := enrollment.ClaimRequest{ClaimToken: bundle.ClaimToken, ControllerURL: *publicURL,
		ControllerPublicKey: security.Encode(c.caKey.Public().(ed25519.PublicKey)),
		NodeCertificatePEM:  nodeCertificate, ControllerCAPEM: c.caPEM}
	if err := postClaim(claimURL, claim); err != nil {
		return err
	}
	log.Printf("node %s claimed; waiting for the outbound control channel", bundle.NodeID)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}

func (c *controller) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/nodes/connect", func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		ctx := r.Context()
		_, hello, err := connection.Read(ctx)
		if err != nil {
			return
		}
		log.Printf("control hello: %s", hello)
		credential, _ := security.RandomToken(32)
		deviceID, _ := security.UUID()
		now := time.Now().UTC()
		planPolicy, _ := c.plan.Policy()
		device := map[string]any{"deviceId": deviceID, "credentialHash": security.Hash(credential), "plan": c.plan,
			"active": true, "subscriptionEnds": now.Add(30 * 24 * time.Hour), "periodEnds": now.Add(30 * 24 * time.Hour),
			"quotaBytes": planPolicy.QuotaBytes, "leaseBytes": planPolicy.QuotaBytes, "leaseExpires": now.Add(24 * time.Hour)}
		if err := write(connection, "device.upsert", device); err != nil {
			return
		}
		feed := compliance.SignedFeed{Version: "mock-1", UpdatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
			Rules: json.RawMessage(`{"blockedDomains":[],"blockedCidrs":[],"blockedPorts":[]}`)}
		if err := compliance.Sign(&feed, c.caKey); err != nil {
			return
		}
		if err := write(connection, "compliance.feed", feed); err != nil {
			return
		}
		log.Printf("test device issued: id=%s plan=%s credential=%s", deviceID, c.plan, credential)
		for {
			_, message, err := connection.Read(ctx)
			if err != nil {
				return
			}
			log.Printf("node: %s", message)
			var envelope struct {
				Type string          `json:"type"`
				Data json.RawMessage `json:"data"`
			}
			if json.Unmarshal(message, &envelope) == nil && envelope.Type == "usage.batch" {
				var batch struct {
					Events []struct {
						EventID int64 `json:"eventId"`
					} `json:"events"`
				}
				if json.Unmarshal(envelope.Data, &batch) == nil {
					ids := make([]int64, 0, len(batch.Events))
					for _, event := range batch.Events {
						ids = append(ids, event.EventID)
					}
					_ = write(connection, "usage.ack", map[string]any{"eventIds": ids})
				}
			}
		}
	})
	return mux
}

func newController(host string, plan model.Plan) (*controller, error) {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RiseVPN Mock Controller CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		serverTemplate.IPAddresses = []net.IP{ip}
	} else {
		serverTemplate.DNSNames = []string{host}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, serverPublic, caPrivate)
	if err != nil {
		return nil, err
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(serverPrivate)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	if err != nil {
		return nil, err
	}
	return &controller{caCert: caCert, caKey: caPrivate,
		caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), serverCert: pair, plan: plan}, nil
}

func (c *controller) issueNodeCertificate(public ed25519.PublicKey, nodeID string) (string, error) {
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: nodeID},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, c.caCert, public, c.caKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

func decodeBundle(value string) (enrollment.Bundle, error) {
	if !strings.HasPrefix(value, enrollment.BundlePrefix) {
		return enrollment.Bundle{}, errors.New("invalid enrollment prefix")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, enrollment.BundlePrefix))
	if err != nil {
		return enrollment.Bundle{}, err
	}
	var bundle enrollment.Bundle
	err = json.Unmarshal(payload, &bundle)
	return bundle, err
}

func postClaim(endpoint string, claim enrollment.ClaimRequest) error {
	payload, _ := json.Marshal(claim)
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("claim returned HTTP %d", response.StatusCode)
	}
	return nil
}

func write(connection *websocket.Conn, messageType string, data any) error {
	payload, _ := json.Marshal(map[string]any{"type": messageType, "data": data})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return connection.Write(ctx, websocket.MessageText, payload)
}
