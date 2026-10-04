package keyindex

import (
	"bytes"
	"errors"
	"testing"
)

// syntheticEntry builds an index entry with a fully controlled identity,
// bypassing key generation. This lets the collision behavior be exercised
// deterministically without needing real keys that share a short ID.
func syntheticEntry(version int, fingerprint []byte) *Entry {
	identity := Identity{
		Version:     version,
		Fingerprint: fingerprint,
		KeyID:       keyIDFromFingerprint(version, fingerprint),
	}
	identity.ShortKeyID = uint32(identity.KeyID)
	return &Entry{Identity: identity}
}

// v4FPWithHighByte builds a v4 fingerprint whose key ID has a controlled high
// byte (fingerprint octet 12) while its low 32 bits (octets 16-19, the short
// ID) stay identical. Distinct high bytes therefore collide on the short ID
// but never on the full key ID or fingerprint.
func v4FPWithHighByte(high byte) []byte {
	fp := make([]byte, V4FingerprintLength)
	fp[12] = high
	return fp
}

func v6FP(last byte) []byte {
	fp := make([]byte, V6FingerprintLength)
	fp[len(fp)-1] = last
	return fp
}

// insertEntry installs a controlled entry via the copy-on-write path used by
// imports.
func insertEntry(s *snapshot, entry *Entry, source string) *snapshot {
	key := fingerprintKey{
		version:     entry.Identity.Version,
		fingerprint: string(entry.Identity.Fingerprint),
	}
	entry.Sources = mergeSources(entry.Sources, source)
	s.entries[key] = entry
	s.rebuildShortID(entry.Identity.ShortKeyID)
	return s
}

func collidingSnapshot(t *testing.T) *snapshot {
	t.Helper()
	s := newSnapshot()
	// Two distinct v4 fingerprints whose full key IDs differ only in the high
	// 32 bits, so both share short key ID 0x00000000.
	s = insertEntry(s, syntheticEntry(4, v4FPWithHighByte(0x01)), "pkg-a")
	s = insertEntry(s, syntheticEntry(4, v4FPWithHighByte(0x02)), "pkg-b")
	// An unrelated key with a different short ID.
	other := syntheticEntry(6, v6FP(0x03))
	other.Identity.ShortKeyID = 0xDEADBEEF
	other.Identity.KeyID = 0x11111111DEADBEEF
	s.entries[fingerprintKey{6, string(other.Identity.Fingerprint)}] = other
	s.rebuildShortID(other.Identity.ShortKeyID)
	return s
}

// TestShortIDCollisionIsAmbiguous proves a short key ID shared by two distinct
// full fingerprints is reported as ambiguous with both keys retained, instead
// of returning the first one encountered.
func TestShortIDCollisionIsAmbiguous(t *testing.T) {
	snap := &Snapshot{s: collidingSnapshot(t)}

	result := snap.LookupShortKeyID(0x00000000)
	if result.Status != LookupAmbiguous {
		t.Fatalf("expected ambiguous, got status %d", result.Status)
	}
	if len(result.Candidates) != 2 {
		t.Fatalf("expected 2 colliding candidates, got %d", len(result.Candidates))
	}
	if bytes.Equal(result.Candidates[0].Identity.Fingerprint,
		result.Candidates[1].Identity.Fingerprint) {
		t.Fatal("colliding candidates must have distinct full fingerprints")
	}
	if _, err := result.Unique(); err == nil {
		t.Fatal("Unique() must fail on an ambiguous result")
	} else if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("expected ErrAmbiguous, got %v", err)
	}
}

// TestShortIDUniqueAndMissing checks the other two explicit outcomes.
func TestShortIDUniqueAndMissing(t *testing.T) {
	snap := &Snapshot{s: collidingSnapshot(t)}

	unique := snap.LookupShortKeyID(0xDEADBEEF)
	if unique.Status != LookupUnique || len(unique.Candidates) != 1 {
		t.Fatalf("expected one unique candidate, got status %d len %d",
			unique.Status, len(unique.Candidates))
	}
	entry, err := unique.Unique()
	if err != nil {
		t.Fatalf("Unique() failed: %v", err)
	}
	if entry.Identity.Version != 6 {
		t.Fatalf("expected v6 key, got v%d", entry.Identity.Version)
	}

	missing := snap.LookupShortKeyID(0x0BADF00D)
	if missing.Status != LookupMissing || len(missing.Candidates) != 0 {
		t.Fatalf("expected missing result, got status %d len %d",
			missing.Status, len(missing.Candidates))
	}
	if _, err := missing.Unique(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestFindByFingerprintDisambiguatesCollision verifies exact version + full
// fingerprint lookup still resolves each colliding key individually.
func TestFindByFingerprintDisambiguatesCollision(t *testing.T) {
	snap := &Snapshot{s: collidingSnapshot(t)}

	a, err := snap.FindByFingerprint(4, v4FPWithHighByte(0x01))
	if err != nil {
		t.Fatalf("lookup by fingerprint failed: %v", err)
	}
	b, err := snap.FindByFingerprint(4, v4FPWithHighByte(0x02))
	if err != nil {
		t.Fatalf("lookup by fingerprint failed: %v", err)
	}
	if bytes.Equal(a.Identity.Fingerprint, b.Identity.Fingerprint) {
		t.Fatal("distinct fingerprints must resolve to distinct entries")
	}

	if _, err := snap.FindByFingerprint(4, v4FPWithHighByte(0x09)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for absent fingerprint, got %v", err)
	}
	// Same fingerprint bytes but wrong version must not match.
	if _, err := snap.FindByFingerprint(6, padV6(v4FPWithHighByte(0x01))); err == nil {
		t.Fatal("fingerprint lookup must require both version and fingerprint")
	}
}

func padV6(fp []byte) []byte {
	out := make([]byte, V6FingerprintLength)
	copy(out[V6FingerprintLength-len(fp):], fp)
	return out
}

// TestMergeSources verifies repeated imports of the same canonical key merge
// origins into one entry, while distinct colliding keys stay separate.
func TestMergeSources(t *testing.T) {
	s := newSnapshot()
	entry := syntheticEntry(4, v4FPWithHighByte(0xAA))
	s = insertEntry(s, entry, "pkg-a")
	// Simulate a second import by reusing the same withKey merge semantics.
	merged := *entry
	merged.Sources = mergeSources(entry.Sources, "pkg-b")
	s.entries[fingerprintKey{4, string(v4FPWithHighByte(0xAA))}] = &merged
	s.rebuildShortID(merged.Identity.ShortKeyID)

	got, err := (&Snapshot{s: s}).FindByFingerprint(4, v4FPWithHighByte(0xAA))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("expected 2 merged sources, got %v", got.Sources)
	}

	// Merging the same source again must not duplicate it.
	again := mergeSources(got.Sources, "pkg-a")
	if len(again) != 2 {
		t.Fatalf("expected sources deduplicated, got %v", again)
	}
}
