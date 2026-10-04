package keyindex

import "errors"

var (
	// ErrUnsupportedVersion is returned when a key or signature hints at a
	// public key version this package cannot compute identifiers for.
	ErrUnsupportedVersion = errors.New("keyindex: unsupported public key version")

	// ErrFingerprintLength is returned when a fingerprint's length does not
	// match the length implied by its key version (20 bytes for v4,
	// 32 bytes for v5/v6).
	ErrFingerprintLength = errors.New("keyindex: fingerprint length does not match key version")

	// ErrConflictingHints is returned when a signature's issuer key ID and
	// issuer fingerprint subpackets contradict each other.
	ErrConflictingHints = errors.New("keyindex: issuer key ID conflicts with issuer fingerprint")

	// ErrNoIssuerInfo is returned when a signature carries neither an issuer
	// fingerprint nor an issuer key ID to build a query from.
	ErrNoIssuerInfo = errors.New("keyindex: signature carries no issuer information")

	// ErrIdentityMismatch is returned when the cached fingerprint or key ID
	// of a public key does not match the value computed from its canonical
	// serialization.
	ErrIdentityMismatch = errors.New("keyindex: cached key fields do not match canonical encoding")
)
