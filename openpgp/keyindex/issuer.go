package keyindex

import (
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// IssuerQuery is a lookup request derived from a signature's issuer
// subpackets. Exactly one of ByFingerprint or ByKeyID is set.
type IssuerQuery struct {
	// Version is the issuer key version advertised by the signature. It is
	// always set for a fingerprint query; for a key-ID-only query it is 0
	// because a bare key ID carries no version information.
	Version int
	// ByFingerprint is non-nil when the signature provides a full issuer
	// fingerprint. The query must then be resolved exclusively by version and
	// fingerprint; a failed fingerprint lookup MUST NOT silently fall back to
	// a key-ID search.
	ByFingerprint []byte
	// ByKeyID is non-nil only when the signature provides an issuer key ID
	// but no usable issuer fingerprint. It carries the full 64-bit key ID.
	ByKeyID *uint64
}

// IssuerQueryFromSignature builds an IssuerQuery from the issuer information in
// sig. A complete issuer fingerprint always takes precedence:
//
//   - With an issuer fingerprint, the advertised version and the fingerprint
//     length are validated separately, and the fingerprint is the only query
//     used. If an issuer key ID subpacket is also present it must be the key ID
//     derived from that fingerprint; otherwise the two hints contradict each
//     other and ErrIssuerConflict is returned. There is no silent fallback to
//     the short/full key ID when a fingerprint is present.
//   - Without an issuer fingerprint, the full 64-bit issuer key ID is used.
//   - With neither hint, ErrNoIssuerHint is returned.
//
// The issuer data is treated as an unverified hint from the signature only; it
// is not compared against any cached key field here.
func IssuerQueryFromSignature(sig *packet.Signature) (IssuerQuery, error) {
	if sig == nil {
		return IssuerQuery{}, ErrNoIssuerHint
	}

	if len(sig.IssuerFingerprint) > 0 {
		version := int(sig.IssuerKeyVersion)
		if err := ValidateFingerprint(version, sig.IssuerFingerprint); err != nil {
			return IssuerQuery{}, err
		}

		derived := keyIDFromFingerprint(version, sig.IssuerFingerprint)
		if sig.IssuerKeyId != nil && *sig.IssuerKeyId != derived {
			return IssuerQuery{}, fmt.Errorf("%w: fingerprint implies key id %016X but signature lists %016X",
				ErrIssuerConflict, derived, *sig.IssuerKeyId)
		}

		fingerprint := make([]byte, len(sig.IssuerFingerprint))
		copy(fingerprint, sig.IssuerFingerprint)
		return IssuerQuery{
			Version:       version,
			ByFingerprint: fingerprint,
		}, nil
	}

	if sig.IssuerKeyId != nil {
		keyID := *sig.IssuerKeyId
		return IssuerQuery{ByKeyID: &keyID}, nil
	}

	return IssuerQuery{}, ErrNoIssuerHint
}

// ResolveIssuer applies a query built from a signature to an immutable
// snapshot. A fingerprint query is resolved by exact version + fingerprint and
// never falls back to a key-ID lookup: a missing fingerprint simply returns
// ErrNotFound. A key-ID query returns the explicit unique/missing/ambiguous
// Result so collisions remain visible to the caller.
func (snap *Snapshot) ResolveIssuer(query IssuerQuery) (Result, error) {
	if query.ByFingerprint != nil {
		entry, err := snap.FindByFingerprint(query.Version, query.ByFingerprint)
		if err != nil {
			return Result{}, err
		}
		return Result{Status: LookupUnique, Candidates: []*Entry{entry}}, nil
	}
	if query.ByKeyID != nil {
		return snap.LookupFullKeyID(*query.ByKeyID), nil
	}
	return Result{}, ErrNoIssuerHint
}
