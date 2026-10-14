package remoteexec

import (
	"encoding/pem"
	"testing"
)

func leafDER(t *testing.T, id Identity) []byte {
	t.Helper()
	blk, _ := pem.Decode(id.CertPEM)
	if blk == nil {
		t.Fatal("no PEM block in identity certificate")
	}
	return blk.Bytes
}

// The management-role verifier must accept only the Management leaf and reject an Agent
// leaf signed by the same CA — this is what stops a compromised Agent from dialing (and
// controlling) another Agent's listener as though it were Management (보안 리뷰 F8).
func TestCNVerifierBindsManagementRole(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	mgmt, err := ca.IssueManagement()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := ca.IssueAgent("alice")
	if err != nil {
		t.Fatal(err)
	}

	verify := cnVerifier(mgmtCN)
	if err := verify([][]byte{leafDER(t, mgmt)}, nil); err != nil {
		t.Fatalf("management cert should pass the management-role check: %v", err)
	}
	if err := verify([][]byte{leafDER(t, agent)}, nil); err == nil {
		t.Fatal("agent cert (same CA) must be rejected by the management-role verifier")
	}
}
