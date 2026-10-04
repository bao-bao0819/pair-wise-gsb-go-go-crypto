package keyindex

import (
	"errors"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func sigWithIssuer(version int, fingerprint []byte, keyID *uint64) *packet.Signature {
	sig := &packet.Signature{}
	if fingerprint != nil {
		sig.IssuerKeyVersion = uint8(version)
		sig.IssuerFingerprint = fingerprint
	}
	sig.IssuerKeyId = keyID
	return sig
}

func uint64Ptr(v uint64) *uint64 { return &v }

func TestQueryFromSignaturePrefersFingerprint(t *testing.T) {
	ix := NewIndex()
	identity := fakeIdentity(t, 6, 0x1122334455667788, 0x5A)
	record := ix.addIdentity(identity, nil, false, "keyring")
	snap := ix.Snapshot()
	sig := sigWithIssuer(6, identity.Fingerprint, uint64Ptr(identity.KeyID))
	query, err := QueryFromSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	res, err := query.Resolve(snap)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != Unique || res.Record != record {
		t.Fatalf("got %v, want unique", res.Status)
	}
}

func TestQueryFromSignatureNoSilentFallback(t *testing.T) {
	ix := NewIndex()
	// The index holds a key with key ID K, but the signature hints at an
	// unknown fingerprint (whose key ID also happens to be K).
	ix.addIdentity(fakeIdentity(t, 4, 0xDEADBEEF, 0x01), nil, false, "keyring")
	snap := ix.Snapshot()
	unknown := fakeIdentity(t, 4, 0xDEADBEEF, 0x02)
	sig := sigWithIssuer(4, unknown.Fingerprint, uint64Ptr(unknown.KeyID))
	query, err := QueryFromSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	res, err := query.Resolve(snap)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != Missing {
		t.Fatalf("fingerprint miss silently fell back to key id: got %v", res.Status)
	}
}

func TestQueryFromSignatureKeyIDOnly(t *testing.T) {
	ix := NewIndex()
	ix.addIdentity(fakeIdentity(t, 4, 55, 0x01), nil, false, "a")
	ix.addIdentity(fakeIdentity(t, 4, 55, 0x02), nil, false, "b")
	snap := ix.Snapshot()
	query, err := QueryFromSignature(sigWithIssuer(0, nil, uint64Ptr(55)))
	if err != nil {
		t.Fatal(err)
	}
	res, err := query.Resolve(snap)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != Ambiguous || len(res.Candidates) != 2 {
		t.Fatalf("got %v with %d candidates, want ambiguous with 2", res.Status, len(res.Candidates))
	}
	query, err = QueryFromSignature(sigWithIssuer(0, nil, uint64Ptr(56)))
	if err != nil {
		t.Fatal(err)
	}
	res, err = query.Resolve(snap)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != Missing {
		t.Fatalf("got %v, want missing", res.Status)
	}
}

func TestQueryFromSignatureRejectsBadHints(t *testing.T) {
	good := fakeIdentity(t, 4, 0xA5A5, 0x01)
	// Unsupported version.
	_, err := QueryFromSignature(sigWithIssuer(3, good.Fingerprint, nil))
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("bad version: got %v, want ErrUnsupportedVersion", err)
	}
	// Fingerprint length not matching its version.
	_, err = QueryFromSignature(sigWithIssuer(4, make([]byte, 32), nil))
	if !errors.Is(err, ErrFingerprintLength) {
		t.Errorf("bad length: got %v, want ErrFingerprintLength", err)
	}
	_, err = QueryFromSignature(sigWithIssuer(6, make([]byte, 20), nil))
	if !errors.Is(err, ErrFingerprintLength) {
		t.Errorf("bad length: got %v, want ErrFingerprintLength", err)
	}
	// Key ID contradicting the fingerprint.
	_, err = QueryFromSignature(sigWithIssuer(4, good.Fingerprint, uint64Ptr(good.KeyID^1)))
	if !errors.Is(err, ErrConflictingHints) {
		t.Errorf("conflicting hints: got %v, want ErrConflictingHints", err)
	}
	// No issuer information at all.
	_, err = QueryFromSignature(&packet.Signature{})
	if !errors.Is(err, ErrNoIssuerInfo) {
		t.Errorf("no issuer info: got %v, want ErrNoIssuerInfo", err)
	}
}
