package keyindex

import (
	"errors"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func sigWithFingerprint(version int, fingerprint []byte, keyID *uint64) *packet.Signature {
	return &packet.Signature{
		IssuerKeyVersion:  uint8(version),
		IssuerFingerprint: fingerprint,
		IssuerKeyId:       keyID,
	}
}

// TestIssuerQueryFingerprintPreferred ensures a full issuer fingerprint is
// used verbatim and a matching key-ID hint does not change the query.
func TestIssuerQueryFingerprintPreferred(t *testing.T) {
	fp := v4FPWithHighByte(0x42)
	derived := keyIDFromFingerprint(4, fp)

	q, err := IssuerQueryFromSignature(sigWithFingerprint(4, fp, &derived))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.ByFingerprint == nil {
		t.Fatal("expected a fingerprint query")
	}
	if q.ByKeyID != nil {
		t.Fatal("fingerprint query must not also carry a key-id fallback")
	}
	if q.Version != 4 || string(q.ByFingerprint) != string(fp) {
		t.Fatalf("unexpected fingerprint query: %+v", q)
	}

	// A fingerprint alone, without any key-ID subpacket, is equally valid.
	q2, err := IssuerQueryFromSignature(sigWithFingerprint(4, fp, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q2.ByKeyID != nil || q2.ByFingerprint == nil {
		t.Fatal("fingerprint-only signature must produce a fingerprint query")
	}
}

// TestIssuerQueryNoFallbackOnMissingFingerprint proves a fingerprint query is
// never silently downgraded to a key-ID search when the key is absent.
func TestIssuerQueryNoFallbackOnMissingFingerprint(t *testing.T) {
	snap := &Snapshot{s: collidingSnapshot(t)}
	fp := v4FPWithHighByte(0x77) // not indexed
	derived := keyIDFromFingerprint(4, fp)

	q, err := IssuerQueryFromSignature(sigWithFingerprint(4, fp, &derived))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := snap.ResolveIssuer(q); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound with no fallback, got %v", err)
	}
}

// TestIssuerQueryContradictoryHints rejects a fingerprint and key ID that do
// not correspond, instead of choosing one silently.
func TestIssuerQueryContradictoryHints(t *testing.T) {
	fp := v4FPWithHighByte(0x42)
	wrong := keyIDFromFingerprint(4, fp) ^ 0x1

	_, err := IssuerQueryFromSignature(sigWithFingerprint(4, fp, &wrong))
	if !errors.Is(err, ErrIssuerConflict) {
		t.Fatalf("expected ErrIssuerConflict, got %v", err)
	}
}

// TestIssuerQueryVersionAndLengthErrors ensure version and fingerprint-length
// problems are reported separately and explicitly.
func TestIssuerQueryVersionAndLengthErrors(t *testing.T) {
	t.Run("unsupported version", func(t *testing.T) {
		_, err := IssuerQueryFromSignature(sigWithFingerprint(5, make([]byte, 32), nil))
		if !errors.Is(err, ErrInvalidVersion) {
			t.Fatalf("expected ErrInvalidVersion, got %v", err)
		}
	})
	t.Run("v4 fingerprint with v6 length", func(t *testing.T) {
		_, err := IssuerQueryFromSignature(sigWithFingerprint(4, make([]byte, 32), nil))
		if !errors.Is(err, ErrInvalidFingerprint) {
			t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
		}
	})
	t.Run("v6 fingerprint with v4 length", func(t *testing.T) {
		_, err := IssuerQueryFromSignature(sigWithFingerprint(6, make([]byte, 20), nil))
		if !errors.Is(err, ErrInvalidFingerprint) {
			t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
		}
	})
}

// TestIssuerQueryKeyIDFallback uses the key ID only when no fingerprint is
// advertised, and reports collisions explicitly through the Result.
func TestIssuerQueryKeyIDFallback(t *testing.T) {
	snap := &Snapshot{s: collidingSnapshot(t)}

	var id uint64 = 0x0100000000000000 // full key id of the first colliding key
	sig := &packet.Signature{IssuerKeyId: &id}

	q, err := IssuerQueryFromSignature(sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.ByFingerprint != nil || q.ByKeyID == nil {
		t.Fatal("expected a key-ID-only query")
	}
	result, err := snap.ResolveIssuer(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != LookupUnique {
		t.Fatalf("full key id should uniquely match, got status %d", result.Status)
	}

	// No hints at all.
	if _, err := IssuerQueryFromSignature(&packet.Signature{}); !errors.Is(err, ErrNoIssuerHint) {
		t.Fatalf("expected ErrNoIssuerHint, got %v", err)
	}
	if _, err := IssuerQueryFromSignature(nil); !errors.Is(err, ErrNoIssuerHint) {
		t.Fatalf("expected ErrNoIssuerHint for nil sig, got %v", err)
	}
}

// TestIssuerResolveFingerprintHitsCollidingKey verifies a fingerprint query
// resolves uniquely even when the target shares its short ID with another key.
func TestIssuerResolveFingerprintHitsCollidingKey(t *testing.T) {
	snap := &Snapshot{s: collidingSnapshot(t)}
	fp := v4FPWithHighByte(0x02)
	derived := keyIDFromFingerprint(4, fp)

	q, err := IssuerQueryFromSignature(sigWithFingerprint(4, fp, &derived))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, err := snap.ResolveIssuer(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != LookupUnique {
		t.Fatalf("expected unique fingerprint match despite short-id collision, got %d", result.Status)
	}
	if string(result.Candidates[0].Identity.Fingerprint) != string(fp) {
		t.Fatal("resolved the wrong colliding key")
	}
}
