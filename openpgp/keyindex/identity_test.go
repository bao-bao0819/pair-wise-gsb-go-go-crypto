package keyindex

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestIdentityOfMatchesParsedKeys(t *testing.T) {
	for _, sample := range keySamples {
		entity := readSampleEntity(t, sample.path)
		keys := allPublicKeys(entity)
		if len(keys) != len(sample.fingerprints) {
			t.Fatalf("%s: expected %d keys, got %d", sample.path, len(sample.fingerprints), len(keys))
		}
		for i, pk := range keys {
			identity, err := IdentityOf(pk)
			if err != nil {
				t.Fatalf("%s key %d: %v", sample.path, i, err)
			}
			if identity.Version != pk.Version {
				t.Errorf("%s key %d: version %d, want %d", sample.path, i, identity.Version, pk.Version)
			}
			if got := hex.EncodeToString(identity.Fingerprint); got != sample.fingerprints[i] {
				t.Errorf("%s key %d: fingerprint %s, want %s", sample.path, i, got, sample.fingerprints[i])
			}
			if identity.KeyID != pk.KeyId {
				t.Errorf("%s key %d: key id %016X, want %016X", sample.path, i, identity.KeyID, pk.KeyId)
			}
		}
	}
}

func TestIdentityOfIgnoresCachedFields(t *testing.T) {
	entity := readSampleEntity(t, keySamples[0].path)
	pk := entity.PrimaryKey

	want, err := IdentityOf(pk)
	if err != nil {
		t.Fatal(err)
	}

	// Clearing the cached fields must not change the computed identity:
	// they are recomputed from the canonical serialization.
	pk.Fingerprint = nil
	pk.KeyId = 0
	got, err := IdentityOf(pk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Fingerprint, want.Fingerprint) || got.KeyID != want.KeyID {
		t.Errorf("identity changed after clearing cached fields: got %X/%016X, want %X/%016X",
			got.Fingerprint, got.KeyID, want.Fingerprint, want.KeyID)
	}
}

func TestIdentityOfRejectsForgedCachedFields(t *testing.T) {
	for _, sample := range keySamples {
		entity := readSampleEntity(t, sample.path)
		pk := entity.PrimaryKey

		realFingerprint := pk.Fingerprint
		forged := append([]byte(nil), realFingerprint...)
		forged[0] ^= 0xFF
		pk.Fingerprint = forged
		if _, err := IdentityOf(pk); !errors.Is(err, ErrIdentityMismatch) {
			t.Errorf("%s: forged cached fingerprint: got %v, want ErrIdentityMismatch", sample.path, err)
		}
		pk.Fingerprint = realFingerprint

		realKeyID := pk.KeyId
		pk.KeyId = realKeyID ^ 1
		if _, err := IdentityOf(pk); !errors.Is(err, ErrIdentityMismatch) {
			t.Errorf("%s: forged cached key id: got %v, want ErrIdentityMismatch", sample.path, err)
		}
		pk.KeyId = realKeyID
	}
}

func TestIdentityOfRejectsUnsupportedVersion(t *testing.T) {
	entity := readSampleEntity(t, keySamples[0].path)
	pk := entity.PrimaryKey
	pk.Version = 3
	if _, err := IdentityOf(pk); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("got %v, want ErrUnsupportedVersion", err)
	}
}
