package keyindex

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Supported key versions. Only v4 and v6 public keys and subkeys are indexed.
const (
	// V4FingerprintLength is the SHA-1 fingerprint length of v4 keys,
	// as defined in RFC 4880, section 12.2.
	V4FingerprintLength = 20
	// V6FingerprintLength is the SHA-256 fingerprint length of v6 keys,
	// as defined in RFC 9580, section 5.1.1.
	V6FingerprintLength = 32
	// KeyIDLength is the length in bytes of a full (64-bit) key ID.
	KeyIDLength = 8
	// ShortKeyIDLength is the length in bytes of the conventional 32-bit
	// short key ID of v4 keys; it equals the last four octets of the
	// fingerprint and therefore of the full key ID.
	ShortKeyIDLength = 4
)

// Identity is the canonical identity of a single public key packet (a primary
// key or a subkey). All fields are derived by recomputing the fingerprint from
// the key's canonical representation; Identity values carry no trust
// information.
type Identity struct {
	// Version is the public key packet version (4 or 6).
	Version int
	// Fingerprint is the recomputed canonical fingerprint (20 bytes for v4,
	// 32 bytes for v6). The backing array is owned by the Identity and must
	// not be modified by the caller.
	Fingerprint []byte
	// KeyID is the full 64-bit key ID derived from the fingerprint.
	KeyID uint64
	// ShortKeyID is the conventional 32-bit short key ID: the low 32 bits of
	// KeyID, equal to the last four fingerprint octets.
	ShortKeyID uint32
}

var (
	// ErrNilPublicKey is returned when a nil *packet.PublicKey is provided.
	ErrNilPublicKey = errors.New("keyindex: nil public key")
	// ErrUnsupportedVersion is returned for key packet versions the index
	// does not support. Only v4 and v6 keys are covered.
	ErrUnsupportedVersion = errors.New("keyindex: unsupported public key version (only v4 and v6 are supported)")
	// ErrFingerprintMismatch is returned when the fingerprint cached on a
	// PublicKey does not match the fingerprint recomputed from its canonical
	// representation.
	ErrFingerprintMismatch = errors.New("keyindex: cached fingerprint does not match canonical representation")
	// ErrKeyIDMismatch is returned when the key ID cached on a PublicKey does
	// not match the key ID derived from the recomputed fingerprint.
	ErrKeyIDMismatch = errors.New("keyindex: cached key id does not match canonical representation")
)

// fingerprintLengthForVersion returns the canonical fingerprint length for the
// given key packet version, or 0 for versions the index does not cover.
func fingerprintLengthForVersion(version int) int {
	switch version {
	case 4:
		return V4FingerprintLength
	case 6:
		return V6FingerprintLength
	default:
		return 0
	}
}

// ComputeIdentity derives the canonical Identity of pk from its canonical
// representation and verifies that the Fingerprint and KeyId fields cached on
// the packet are consistent with it. Neither cached field is trusted: both are
// recomputed, and any discrepancy is reported as an error rather than silently
// used.
func ComputeIdentity(pk *packet.PublicKey) (Identity, error) {
	if pk == nil {
		return Identity{}, ErrNilPublicKey
	}
	wantLen := fingerprintLengthForVersion(pk.Version)
	if wantLen == 0 {
		return Identity{}, fmt.Errorf("%w: got version %d", ErrUnsupportedVersion, pk.Version)
	}

	fingerprint, err := canonicalFingerprint(pk)
	if err != nil {
		return Identity{}, err
	}

	identity := Identity{
		Version:     pk.Version,
		Fingerprint: fingerprint,
		KeyID:       keyIDFromFingerprint(pk.Version, fingerprint),
	}
	identity.ShortKeyID = uint32(identity.KeyID)

	// Cross-check the cached fields instead of accepting them as fact.
	if len(pk.Fingerprint) != 0 && !bytes.Equal(pk.Fingerprint, fingerprint) {
		return Identity{}, fmt.Errorf("%w: version %d", ErrFingerprintMismatch, pk.Version)
	}
	if pk.KeyId != 0 || len(pk.Fingerprint) != 0 {
		if pk.KeyId != identity.KeyID {
			return Identity{}, fmt.Errorf("%w: version %d", ErrKeyIDMismatch, pk.Version)
		}
	}
	return identity, nil
}

// canonicalFingerprint recomputes the fingerprint of pk from the exact wire
// representation hashed for signatures (packet.PublicKey.SerializeForHash).
func canonicalFingerprint(pk *packet.PublicKey) ([]byte, error) {
	var sum []byte
	if pk.Version >= 5 {
		hash := sha256.New()
		if err := pk.SerializeForHash(hash); err != nil {
			return nil, fmt.Errorf("keyindex: failed to serialize v6 key for hashing: %w", err)
		}
		sum = hash.Sum(nil)
	} else {
		hash := sha1.New()
		if err := pk.SerializeForHash(hash); err != nil {
			return nil, fmt.Errorf("keyindex: failed to serialize v4 key for hashing: %w", err)
		}
		sum = hash.Sum(nil)
	}
	fingerprint := make([]byte, fingerprintLengthForVersion(pk.Version))
	copy(fingerprint, sum)
	return fingerprint, nil
}

// keyIDFromFingerprint derives the full 64-bit key ID from a canonical
// fingerprint: the first eight fingerprint octets for v6 keys, or the last
// eight octets for v4 keys.
func keyIDFromFingerprint(version int, fingerprint []byte) uint64 {
	if version >= 5 {
		return binary.BigEndian.Uint64(fingerprint[:KeyIDLength])
	}
	return binary.BigEndian.Uint64(fingerprint[len(fingerprint)-KeyIDLength:])
}
