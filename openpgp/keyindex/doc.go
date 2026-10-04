// Package keyindex is a trust-free index of public keys for offline signature
// verification tools.
//
// # What this package does
//
// Over time an offline verification workflow accumulates many public key
// packages. Looking a signer up by the conventional 32-bit short key ID is no
// longer safe at that scale: key IDs are not unique, and returning the first
// matching key silently verifies signatures against the wrong key. keyindex
// answers identity questions only:
//
//   - Exact lookup by key packet version plus the complete fingerprint.
//   - Key-ID lookup that reports an explicit unique, missing, or ambiguous
//     result, retaining every key involved in a collision.
//
// Both v4 and v6 primary keys and subkeys are indexed. Importing the same
// canonical key more than once merges the recorded import sources instead of
// creating a duplicate entry; two genuinely different keys that happen to
// share a short ID are both retained and reported as ambiguous.
//
// # No trust judgments
//
// Finding a key here means only that key material with the requested
// identifier has previously been imported. It does NOT mean the key is
// trustworthy, non-revoked, unexpired, well-formed with respect to
// self-signatures, or bound to any particular user ID. Callers MUST verify
// the signature cryptographically and apply their own trust policy before
// treating a result as the signer. This package deliberately performs none of
// that validation.
//
// # Canonical identity, not cached fields
//
// Fingerprints and key IDs are recomputed from the canonical representation
// of each packet.PublicKey (SerializeForHash, per RFC 4880 section 12.2 for v4
// and RFC 9580 for v6). Caller-populated Fingerprint/KeyId fields are never
// accepted as fact; when present they are merely cross-checked and a mismatch
// is an error.
//
// # Resolving a signature's issuer
//
// Use IssuerQueryFromSignature to build a query from a signature's issuer
// subpackets. When the signature carries a full issuer fingerprint it takes
// precedence and a missing fingerprint match is never silently retried with a
// short key ID. A fingerprint and a key ID that contradict each other, an
// unsupported issuer version, and a fingerprint whose length does not match
// its version are all distinct errors. Only a signature with no fingerprint
// falls back to its full 64-bit issuer key ID, and even then ambiguity is
// surfaced rather than hidden.
//
// # Concurrency
//
// Snapshot returns an immutable read-only view. Snapshots may be queried from
// many goroutines concurrently; subsequent Add calls build a new view and can
// never change the length, order, or contents of a candidate slice that an
// earlier snapshot is already iterating.
//
// # Example
//
//	ix := keyindex.New()
//	for _, pkg := range keyPackages {
//	    entities, err := openpgp.ReadArmoredKeyRing(pkg)
//	    if err != nil { /* ... */ }
//	    for _, entity := range entities {
//	        if err := ix.AddEntity(entity, pkgName); err != nil { /* ... */ }
//	    }
//	}
//
//	snap := ix.Snapshot()
//	query, err := keyindex.IssuerQueryFromSignature(signature)
//	if err != nil { /* contradictory or malformed issuer hints */ }
//	result, err := snap.ResolveIssuer(query)
//	if err != nil { /* fingerprint/key not found */ }
//	signer, err := result.Unique() // fails on ambiguity
//	if err != nil { /* ask for a full fingerprint */ }
//	// signer is located, but still NOT trusted: verify the signature and
//	// apply trust policy independently.
package keyindex
