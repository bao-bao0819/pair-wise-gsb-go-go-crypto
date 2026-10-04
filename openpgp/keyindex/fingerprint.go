package keyindex

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidVersion is returned when a claimed key version is not one of
	// the supported versions (4 and 6).
	ErrInvalidVersion = errors.New("keyindex: invalid or unsupported issuer key version")
	// ErrInvalidFingerprint is returned when a fingerprint is empty or its
	// length does not match the claimed version (20 bytes for v4, 32 for v6).
	ErrInvalidFingerprint = errors.New("keyindex: fingerprint length does not match key version")
	// ErrIssuerConflict is returned when a signature carries both a full
	// issuer fingerprint and an issuer key ID that are inconsistent with each
	// other. Such a signature is never resolved by silently preferring either
	// hint.
	ErrIssuerConflict = errors.New("keyindex: signature issuer fingerprint and key id contradict each other")
	// ErrNoIssuerHint is returned when a signature advertises neither an
	// issuer fingerprint nor an issuer key ID, so no query can be built.
	ErrNoIssuerHint = errors.New("keyindex: signature contains neither issuer fingerprint nor issuer key id")
)

// ValidateFingerprint checks that version is a supported version and that
// fingerprint has the canonical length for it. It reports version problems and
// length problems as distinct errors wrapping ErrInvalidVersion and
// ErrInvalidFingerprint respectively.
func ValidateFingerprint(version int, fingerprint []byte) error {
	wantLen := fingerprintLengthForVersion(version)
	if wantLen == 0 {
		return fmt.Errorf("%w: got version %d", ErrInvalidVersion, version)
	}
	if len(fingerprint) != wantLen {
		return fmt.Errorf("%w: version %d requires %d bytes, got %d",
			ErrInvalidFingerprint, version, wantLen, len(fingerprint))
	}
	return nil
}
