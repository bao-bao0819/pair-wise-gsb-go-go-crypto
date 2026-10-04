package keyindex

import (
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// A Query is a lookup request, typically derived from a signature's issuer
// subpackets. Build one with QueryFromSignature, or directly with
// QueryFingerprint / QueryKeyID.
type Query struct {
	version     int
	fingerprint []byte
	keyID       uint64
	hasKeyID    bool
}

// QueryFingerprint returns a Query for an exact version + full fingerprint
// match.
func QueryFingerprint(version int, fingerprint []byte) Query {
	return Query{version: version, fingerprint: fingerprint}
}

// QueryKeyID returns a Query resolved by 64-bit key ID, which may be
// ambiguous.
func QueryKeyID(keyID uint64) Query {
	return Query{keyID: keyID, hasKeyID: true}
}

// QueryFromSignature builds a Query from a signature's issuer information.
//
// The issuer fingerprint subpacket, when present, is authoritative: the
// query matches only that exact version and fingerprint, and resolution
// never falls back to the key ID. The issuer key ID subpacket, when also
// present, must agree with the fingerprint or ErrConflictingHints is
// returned. A hinted version this package does not support, or a
// fingerprint whose length does not match its version, is rejected with
// ErrUnsupportedVersion or ErrFingerprintLength respectively. Only when no
// fingerprint is present at all does the query fall back to the issuer key
// ID alone. A signature with neither hint yields ErrNoIssuerInfo.
func QueryFromSignature(sig *packet.Signature) (Query, error) {
	if sig.IssuerFingerprint != nil && sig.IssuerKeyVersion != 0 {
		version := int(sig.IssuerKeyVersion)
		keyID, err := keyIDFromFingerprint(version, sig.IssuerFingerprint)
		if err != nil {
			return Query{}, err
		}
		if sig.IssuerKeyId != nil && *sig.IssuerKeyId != keyID {
			return Query{}, fmt.Errorf("%w: key id %016X does not match version %d fingerprint %X",
				ErrConflictingHints, *sig.IssuerKeyId, version, sig.IssuerFingerprint)
		}
		return QueryFingerprint(version, sig.IssuerFingerprint), nil
	}
	if sig.IssuerKeyId != nil {
		return QueryKeyID(*sig.IssuerKeyId), nil
	}
	return Query{}, ErrNoIssuerInfo
}

// Resolve runs the query against a snapshot. A fingerprint query reports
// Missing when the exact key is absent, even if the snapshot holds other
// keys with the same key ID: the full fingerprint is authoritative and
// there is deliberately no silent downgrade to a short identifier.
func (q Query) Resolve(s *Snapshot) (Result, error) {
	if q.fingerprint != nil {
		return s.ByFingerprint(q.version, q.fingerprint)
	}
	if q.hasKeyID {
		return s.ByKeyID(q.keyID), nil
	}
	return Result{Status: Missing}, ErrNoIssuerInfo
}
