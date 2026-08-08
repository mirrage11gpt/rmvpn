package controlplane

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/enrollment"
	"github.com/mirrage11gpt/rmvpn/internal/security"
)

type NodeIssuer struct {
	certificate    *x509.Certificate
	signer         crypto.Signer
	certificatePEM string
}

func LoadNodeIssuer(certFile, keyFile string) (*NodeIssuer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, errors.New("node CA PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("node CA key is not a signer")
	}
	return &NodeIssuer{certificate: certificate, signer: signer, certificatePEM: string(certPEM)}, nil
}

func (i *NodeIssuer) Issue(nodeID string, publicKey ed25519.PublicKey, now time.Time) (string, *x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: i.certificate.Subject, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	template.Subject.CommonName = "risevpn-node:" + nodeID
	der, err := x509.CreateCertificate(rand.Reader, template, i.certificate, publicKey, i.signer)
	if err != nil {
		return "", nil, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), template, nil
}

func decodeBundle(value string) (enrollment.Bundle, error) {
	var bundle enrollment.Bundle
	if !strings.HasPrefix(value, enrollment.BundlePrefix) {
		return bundle, errors.New("bundle must start with rvpn1_")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, enrollment.BundlePrefix))
	if err != nil {
		return bundle, err
	}
	if err = json.Unmarshal(raw, &bundle); err != nil {
		return bundle, err
	}
	if bundle.NodeID == "" || bundle.Domain == "" || bundle.ClaimEndpoint == "" || bundle.ClaimToken == "" || !bundle.ExpiresAt.After(time.Now().UTC()) {
		return bundle, errors.New("bundle is invalid or expired")
	}
	return bundle, nil
}

func (a *App) enrollNode(w http.ResponseWriter, r *http.Request) {
	if a.issuer == nil {
		problem(w, 503, "node-ca", "Центр сертификации узлов не настроен", "Подключите online intermediate key и certificate.")
		return
	}
	var body struct {
		Bundle string `json:"bundle"`
	}
	if decode(r, &body) != nil {
		problem(w, 400, "bundle", "Не удалось прочитать ключ", "")
		return
	}
	bundle, err := decodeBundle(strings.TrimSpace(body.Bundle))
	if err != nil {
		problem(w, 400, "bundle", "Ключ локации недействителен", err.Error())
		return
	}
	publicRaw, err := security.Decode(bundle.NodePublicKey)
	if err != nil || len(publicRaw) != ed25519.PublicKeySize {
		problem(w, 400, "node-key", "Публичный ключ узла недействителен", "")
		return
	}
	certificate, parsed, err := a.issuer.Issue(bundle.NodeID, ed25519.PublicKey(publicRaw), time.Now().UTC())
	if err != nil {
		problem(w, 500, "node-cert", "Не удалось выпустить сертификат", "")
		return
	}
	if len(a.config.CompliancePrivateKey) != ed25519.PrivateKeySize {
		problem(w, 503, "controller-key", "Control signing key не настроен", "")
		return
	}
	controllerPublic := ed25519.PrivateKey(a.config.CompliancePrivateKey).Public().(ed25519.PublicKey)
	if len(a.config.QuotaPrivateKey) != ed25519.PrivateKeySize {
		problem(w, 503, "quota-key", "Quota signing key не настроен", "")
		return
	}
	quotaPublic := ed25519.PrivateKey(a.config.QuotaPrivateKey).Public().(ed25519.PublicKey)
	caps, _ := json.Marshal([]string{})
	_, err = a.db.Exec(r.Context(), `INSERT INTO nodes(id,domain,status,agent_version,protocol_version,capabilities,public_key,certificate_serial,certificate_not_after) VALUES($1,$2,'pending',$3,1,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET domain=excluded.domain,public_key=excluded.public_key,certificate_serial=excluded.certificate_serial,certificate_not_after=excluded.certificate_not_after`, bundle.NodeID, bundle.Domain, bundle.AgentVersion, caps, publicRaw, parsed.SerialNumber.String(), parsed.NotAfter)
	if err != nil {
		problem(w, 500, "db", "Не удалось подготовить запись узла", "")
		return
	}
	claim := enrollment.ClaimRequest{ClaimToken: bundle.ClaimToken, ControllerURL: a.config.ControlURL, ControllerPublicKey: security.Encode(controllerPublic), QuotaPublicKey: security.Encode(quotaPublic), CompliancePublicKey: security.Encode(controllerPublic), NodeCertificatePEM: certificate, ControllerCAPEM: a.issuer.certificatePEM}
	payload, _ := json.Marshal(claim)
	request, err := http.NewRequestWithContext(r.Context(), "POST", bundle.ClaimEndpoint, strings.NewReader(string(payload)))
	if err == nil {
		request.Header.Set("Content-Type", "application/json")
		response, callErr := (&http.Client{Timeout: 20 * time.Second}).Do(request)
		if callErr != nil {
			err = callErr
		} else {
			defer response.Body.Close()
			if response.StatusCode/100 != 2 {
				err = fmt.Errorf("claim returned HTTP %d", response.StatusCode)
			}
		}
	}
	if err != nil {
		problem(w, 502, "node-claim", "Узел не подтвердил подключение", err.Error())
		return
	}
	s := currentSession(r)
	_, _ = a.db.Exec(context.Background(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'node.enroll','node',$2,'one-time enrollment',jsonb_build_object('domain',$3))`, s.UserID, bundle.NodeID, bundle.Domain)
	jsonResponse(w, 201, map[string]any{"nodeId": bundle.NodeID, "domain": bundle.Domain, "status": "pending", "certificateNotAfter": parsed.NotAfter})
}
