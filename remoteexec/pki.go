package remoteexec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Autumn-27/artex/mcpconn"
	"math/big"
	"time"
)

// ConnMode selects which side dials the TCP/TLS connection. It is independent of RPC
// direction (Management always calls tools; the Agent always executes). Infra picks
// the mode: if the Agent sits behind NAT, have the Agent dial out (ModeAgentDials);
// if Management cannot reach in, have Management dial the exposed Agent
// (ModeMgmtDials).
type ConnMode string

const (
	// ModeMgmtDials: the Agent listens, Management dials it. Hostname verification of
	// the Agent is intentionally skipped (the sandbox's address is dynamic); the Agent
	// is instead pinned by CA signature + agent id. Management still presents its own
	// client cert, so the channel stays mutually authenticated.
	ModeMgmtDials ConnMode = "mgmt-dials-agent"
	// ModeAgentDials: Management listens, the Agent dials out. The Agent presents its
	// short-lived client cert (verified against the CA); it verifies Management's
	// server cert against the same CA.
	ModeAgentDials ConnMode = "agent-dials-mgmt"
)

// AgentCertTTL is the lifetime of a freshly issued Agent certificate. Per the design,
// Agent certs are short-lived (10 days) and rotated by re-provisioning — the user
// generates a new connection bundle and relaunches the sandbox; there is no on-channel
// renewal.
const AgentCertTTL = 10 * 24 * time.Hour

// managementCertTTL is the lifetime of the Management server/client cert. It is long
// (the control plane is stable and not sandbox-ephemeral) and regenerated only when
// the CA is.
const managementCertTTL = 10 * 365 * 24 * time.Hour

// Identity is a certificate + its private key, both PEM-encoded, plus the CA that
// signed it so a peer can build a trust pool from a single bundle.
type Identity struct {
	CertPEM []byte `json:"cert_pem"`
	KeyPEM  []byte `json:"key_pem"`
}

// TLSCertificate parses the Identity into a usable tls.Certificate.
func (id Identity) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(id.CertPEM, id.KeyPEM)
}

// CA is the control-plane certificate authority. The Management Server owns it; the
// Agent never sees the CA private key — only the CA certificate (for trust) and its
// own issued leaf.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// NewCA mints a fresh control-plane CA.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ARTEX control-plane CA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(managementCertTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  encodeECKey(key),
	}, nil
}

// LoadCA restores a CA from its PEM cert+key (Management persists these under its data
// dir so the CA survives restarts).
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := leaf.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("remoteexec: CA key is not ECDSA")
	}
	return &CA{cert: cert, key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// issueLeaf signs a leaf certificate for the given common name and usages.
func (ca *CA) issueLeaf(cn string, ttl time.Duration, server, client bool) (Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return Identity{}, err
	}
	var eku []x509.ExtKeyUsage
	if server {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	if client {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  eku,
		// No DNS/IP SANs: the channel is pinned by CA + CommonName, not hostname, so
		// the same bundle works regardless of the sandbox's address.
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  encodeECKey(key),
	}, nil
}

// agentCN is the canonical CommonName for an Agent's leaf, carrying the agent id so
// Management can pin on it in ModeMgmtDials.
func agentCN(agentID string) string { return "artex-agent:" + agentID }

// IssueAgent signs a short-lived (AgentCertTTL) client+server cert for an Agent. It is
// both client and server capable so the one cert works in either ConnMode.
func (ca *CA) IssueAgent(agentID string) (Identity, error) {
	return ca.issueLeaf(agentCN(agentID), AgentCertTTL, true, true)
}

// IssueManagement signs the Management Server's long-lived client+server cert.
func (ca *CA) IssueManagement() (Identity, error) {
	return ca.issueLeaf("artex-management", managementCertTTL, true, true)
}

// Bundle is the connection information Management generates and the user injects into
// their sandbox to launch an Agent. ARTEX only produces this; it never launches the
// sandbox. It contains everything the Agent needs and nothing about the LLM.
type Bundle struct {
	Version  int       `json:"version"`
	Mode     ConnMode  `json:"mode"`
	AgentID  string    `json:"agent_id"`
	Address  string    `json:"address"` // ModeMgmtDials: where the Agent listens; ModeAgentDials: where the Agent dials
	CACert   []byte    `json:"ca_cert_pem"`
	Identity Identity  `json:"identity"` // the Agent's short-lived cert+key
	Issued   time.Time `json:"issued_at"`
	Expires  time.Time `json:"expires_at"`
	// MCP lists the MCP servers this Agent should host (snapshot at issue time; change
	// = reissue the bundle, consistent with the one-shot/reprovision model). Env may
	// carry tool secrets (headers/tokens) the Agent needs to execute — NOT LLM secrets,
	// which never leave the control plane. Empty for agents that host no MCP.
	MCP []mcpconn.Config `json:"mcp,omitempty"`
}

// Marshal renders the bundle as indented JSON for the user to save into their sandbox.
func (b *Bundle) Marshal() ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// ParseBundle reads a bundle the Agent was launched with.
func ParseBundle(raw []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("remoteexec: parse bundle: %w", err)
	}
	if b.AgentID == "" || b.Mode == "" || len(b.CACert) == 0 || len(b.Identity.CertPEM) == 0 {
		return nil, errors.New("remoteexec: bundle missing required fields")
	}
	return &b, nil
}

// Expired reports whether the Agent cert in the bundle is past its NotAfter. A sandbox
// launched with an expired bundle must be re-provisioned.
func (b *Bundle) Expired() bool { return !b.Expires.IsZero() && time.Now().After(b.Expires) }

// caPool builds an x509 pool trusting exactly the given CA PEM.
func caPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("remoteexec: invalid CA PEM")
	}
	return pool, nil
}

// pinnedVerifier returns a VerifyPeerCertificate that checks the peer's leaf chains to
// the CA and (when wantCN is non-empty) has exactly that CommonName. Used when
// InsecureSkipVerify disables the stdlib's hostname check but we still demand a valid,
// specific peer — the ModeMgmtDials case for verifying the Agent.
func pinnedVerifier(pool *x509.CertPool, wantCN string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("remoteexec: peer presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		intermediates := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			if c, err := x509.ParseCertificate(raw); err == nil {
				intermediates.AddCert(c)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return fmt.Errorf("remoteexec: peer cert does not chain to CA: %w", err)
		}
		if wantCN != "" && leaf.Subject.CommonName != wantCN {
			return fmt.Errorf("remoteexec: peer cert CN %q != expected %q", leaf.Subject.CommonName, wantCN)
		}
		return nil
	}
}

// AgentListenerTLS builds the server-side config for ModeMgmtDials (the Agent listens).
// It requires and verifies Management's client cert against the CA.
func AgentListenerTLS(bundle *Bundle) (*tls.Config, error) {
	cert, err := bundle.Identity.TLSCertificate()
	if err != nil {
		return nil, err
	}
	pool, err := caPool(bundle.CACert)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// MgmtDialTLS builds the client-side config for ModeMgmtDials (Management dials the
// Agent). Hostname verification is skipped by design; the Agent is pinned by CA +
// agent id instead. mgmtID is Management's own cert (so the Agent can verify us).
func MgmtDialTLS(mgmtID Identity, caPEM []byte, agentID string) (*tls.Config, error) {
	cert, err := mgmtID.TLSCertificate()
	if err != nil {
		return nil, err
	}
	pool, err := caPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		RootCAs:               pool,
		InsecureSkipVerify:    true,                                   // hostname check off (dynamic sandbox address) ...
		VerifyPeerCertificate: pinnedVerifier(pool, agentCN(agentID)), // ... replaced by CA+CN pin
		MinVersion:            tls.VersionTLS12,
	}, nil
}

// MgmtListenerTLS builds the server-side config for ModeAgentDials (Management listens,
// the Agent dials out). It requires and verifies the Agent's short-lived client cert.
func MgmtListenerTLS(mgmtID Identity, caPEM []byte) (*tls.Config, error) {
	cert, err := mgmtID.TLSCertificate()
	if err != nil {
		return nil, err
	}
	pool, err := caPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// AgentDialTLS builds the client-side config for ModeAgentDials (the Agent dials
// Management). The Agent presents its cert and verifies Management against the CA;
// hostname verification is skipped (Management's address may also be dynamic), with a
// CA+CN pin on "artex-management" instead.
func AgentDialTLS(bundle *Bundle) (*tls.Config, error) {
	cert, err := bundle.Identity.TLSCertificate()
	if err != nil {
		return nil, err
	}
	pool, err := caPool(bundle.CACert)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		RootCAs:               pool,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinnedVerifier(pool, "artex-management"),
		MinVersion:            tls.VersionTLS12,
	}, nil
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func encodeECKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
