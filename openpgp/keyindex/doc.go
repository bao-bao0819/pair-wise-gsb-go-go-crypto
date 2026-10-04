// Package keyindex provides a trust-neutral index over OpenPGP public keys.
//
// The index answers one question only: which known public key material
// matches a given identifier. It supports exact lookups by key version and
// full fingerprint, and lookups by 64-bit key ID that report an explicit
// unique, missing, or ambiguous outcome instead of silently returning the
// first match.
//
// Key identities (version, fingerprint, key ID) are always computed from the
// canonical serialization of a packet.PublicKey, or verified against it.
// Cached fields supplied by callers are never taken at face value.
//
// This package makes no trust judgments. A key being present in the index,
// or being returned as a unique match, says nothing about whether the key is
// valid, certified, unexpired, or belongs to anyone in particular. Callers
// must establish trust separately (for example by verifying certifications
// or checking a trust store) before relying on a key returned here.
package keyindex // import "github.com/ProtonMail/go-crypto/openpgp/keyindex"
