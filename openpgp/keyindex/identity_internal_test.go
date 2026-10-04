package keyindex

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func mustRSAKey(t *testing.T) *packet.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	return packet.NewRSAPublicKey(time.Unix(1_700_000_000, 0), &priv.PublicKey)
}

// TestComputeIdentityV4Recomputes verifies the extraction layer derives the
// v4 fingerprint, full key ID and short key ID from the canonical
// representation, and agrees with the packet's own derivation.
func TestComputeIdentityV4Recomputes(t *testing.T) {
	pk := mustRSAKey(t)

	id, err := ComputeIdentity(pk)
	if err != nil {
		t.Fatalf("ComputeIdentity failed: %v", err)
	}
	if id.Version != 4 {
		t.Fatalf("expected version 4, got %d", id.Version)
	}
	if len(id.Fingerprint) != V4FingerprintLength {
		t.Fatalf("expected %d-byte fingerprint, got %d", V4FingerprintLength, len(id.Fingerprint))
	}
	if !bytes.Equal(id.Fingerprint, pk.Fingerprint) {
		t.Fatalf("recomputed fingerprint %X != cached %X", id.Fingerprint, pk.Fingerprint)
	}
	if id.KeyID != pk.KeyId {
		t.Fatalf("recomputed key id %016X != cached %016X", id.KeyID, pk.KeyId)
	}
	if want := uint32(pk.KeyId); id.ShortKeyID != want {
		t.Fatalf("short key id %08X != %08X", id.ShortKeyID, want)
	}
	if want := pk.Fingerprint[16:20]; !bytes.Equal(id.Fingerprint[16:20], want) {
		t.Fatalf("short id not the last four fingerprint octets")
	}
}

// TestComputeIdentityRejectsTamperedFields ensures caller-controlled cached
// fields cannot be smuggled in as facts: any mismatch with the canonical
// representation is reported rather than used.
func TestComputeIdentityRejectsTamperedFields(t *testing.T) {
	t.Run("tampered fingerprint", func(t *testing.T) {
		pk := mustRSAKey(t)
		pk.Fingerprint = bytes.Clone(pk.Fingerprint)
		pk.Fingerprint[0] ^= 0xFF

		_, err := ComputeIdentity(pk)
		if !errors.Is(err, ErrFingerprintMismatch) {
			t.Fatalf("expected ErrFingerprintMismatch, got %v", err)
		}
	})

	t.Run("tampered key id", func(t *testing.T) {
		pk := mustRSAKey(t)
		pk.KeyId ^= 1

		_, err := ComputeIdentity(pk)
		if !errors.Is(err, ErrKeyIDMismatch) {
			t.Fatalf("expected ErrKeyIDMismatch, got %v", err)
		}
	})

	t.Run("unsupported version", func(t *testing.T) {
		pk := mustRSAKey(t)
		pk.Version = 5

		_, err := ComputeIdentity(pk)
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("expected ErrUnsupportedVersion for v5, got %v", err)
		}
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := ComputeIdentity(nil)
		if !errors.Is(err, ErrNilPublicKey) {
			t.Fatalf("expected ErrNilPublicKey, got %v", err)
		}
	})
}

// TestFingerprintLengthForVersion covers the v4/v6 length table and rejects
// other versions.
func TestFingerprintLengthForVersion(t *testing.T) {
	cases := []struct {
		version int
		want    int
	}{
		{3, 0},
		{4, V4FingerprintLength},
		{5, 0},
		{6, V6FingerprintLength},
	}
	for _, c := range cases {
		if got := fingerprintLengthForVersion(c.version); got != c.want {
			t.Errorf("version %d: got length %d, want %d", c.version, got, c.want)
		}
	}
}

// TestKeyIDDerivationVectors checks key ID extraction against fixed byte
// vectors, independently of any generated key.
func TestKeyIDDerivationVectors(t *testing.T) {
	v4FP, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF00112233")
	v6FP, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")

	if got, want := keyIDFromFingerprint(4, v4FP), uint64(0xCCDDEEFF00112233); got != want {
		t.Fatalf("v4 key id = %016X, want %016X", got, want)
	}
	if got, want := keyIDFromFingerprint(6, v6FP), uint64(0x0011223344556677); got != want {
		t.Fatalf("v6 key id = %016X, want %016X", got, want)
	}
	if got, want := uint32(keyIDFromFingerprint(4, v4FP)), uint32(0x00112233); got != want {
		t.Fatalf("v4 short id = %08X, want %08X", got, want)
	}
}

// TestValidateFingerprint ensures version and length problems are reported as
// distinct, separately identifiable errors.
func TestValidateFingerprint(t *testing.T) {
	if err := ValidateFingerprint(4, make([]byte, V4FingerprintLength)); err != nil {
		t.Fatalf("valid v4 fingerprint rejected: %v", err)
	}
	if err := ValidateFingerprint(6, make([]byte, V6FingerprintLength)); err != nil {
		t.Fatalf("valid v6 fingerprint rejected: %v", err)
	}
	if err := ValidateFingerprint(5, make([]byte, 32)); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("expected ErrInvalidVersion, got %v", err)
	}
	if err := ValidateFingerprint(4, make([]byte, 32)); !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("expected ErrInvalidFingerprint for 32-byte v4 fp, got %v", err)
	}
	if err := ValidateFingerprint(6, make([]byte, 20)); !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("expected ErrInvalidFingerprint for 20-byte v6 fp, got %v", err)
	}
	if err := ValidateFingerprint(4, nil); !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("expected ErrInvalidFingerprint for nil fp, got %v", err)
	}
}
