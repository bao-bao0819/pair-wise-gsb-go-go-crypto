package keyindex

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	// FingerprintLengthV4 is the full fingerprint length of a v4 key.
	FingerprintLengthV4 = 20
	// FingerprintLengthV6 is the full fingerprint length of a v5/v6 key.
	FingerprintLengthV6 = 32
)

// A KeyIdentity is the canonical identifier of a public key: its packet
// version, its full fingerprint, and the 64-bit key ID derived from that
// fingerprint. Two keys with different fingerprints are different keys, even
// if their key IDs collide.
type KeyIdentity struct {
	Version     int
	Fingerprint []byte
	KeyID       uint64
}

// fingerprintLength returns the full fingerprint length implied by a public
// key version, or an error for versions this package does not support.
func fingerprintLength(version int) (int, error) {
	switch {
	case version == 4:
		return FingerprintLengthV4, nil
	case version == 5 || version == 6:
		return FingerprintLengthV6, nil
	default:
		return 0, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
}

// computeFingerprint hashes the canonical serialization of pk the same way
// the OpenPGP specifications define: SHA-1 over the v4 hash prefix and body
// for v4 keys, SHA-256 for v5/v6 keys.
func computeFingerprint(pk *packet.PublicKey) ([]byte, error) {
	var h hash.Hash
	switch {
	case pk.Version == 4:
		h = sha1.New()
	case pk.Version == 5 || pk.Version == 6:
		h = sha256.New()
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, pk.Version)
	}
	if err := pk.SerializeForHash(h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// keyIDFromFingerprint derives the 64-bit key ID from a full fingerprint:
// the low 64 bits for v4 keys, the high 64 bits for v5/v6 keys.
func keyIDFromFingerprint(version int, fingerprint []byte) (uint64, error) {
	length, err := fingerprintLength(version)
	if err != nil {
		return 0, err
	}
	if len(fingerprint) != length {
		return 0, fmt.Errorf("%w: version %d key with %d-byte fingerprint",
			ErrFingerprintLength, version, len(fingerprint))
	}
	if version == 4 {
		return binary.BigEndian.Uint64(fingerprint[length-8:]), nil
	}
	return binary.BigEndian.Uint64(fingerprint[:8]), nil
}

// IdentityOf computes the identity of pk from its canonical serialization.
//
// The fingerprint is always recomputed from the key material; it is never
// read from pk.Fingerprint. If pk carries cached values (pk.Fingerprint or
// pk.KeyId set by whoever parsed or constructed it), they are verified
// against the computed identity and any mismatch is reported as
// ErrIdentityMismatch. Callers that need identifiers for keys produced by
// untrusted code can therefore rely on the result without re-validating the
// key themselves.
func IdentityOf(pk *packet.PublicKey) (KeyIdentity, error) {
	fingerprint, err := computeFingerprint(pk)
	if err != nil {
		return KeyIdentity{}, err
	}
	keyID, err := keyIDFromFingerprint(pk.Version, fingerprint)
	if err != nil {
		return KeyIdentity{}, err
	}
	if len(pk.Fingerprint) > 0 && !bytes.Equal(pk.Fingerprint, fingerprint) {
		return KeyIdentity{}, fmt.Errorf("%w: fingerprint", ErrIdentityMismatch)
	}
	if pk.KeyId != 0 && pk.KeyId != keyID {
		return KeyIdentity{}, fmt.Errorf("%w: key id", ErrIdentityMismatch)
	}
	return KeyIdentity{
		Version:     pk.Version,
		Fingerprint: fingerprint,
		KeyID:       keyID,
	}, nil
}
