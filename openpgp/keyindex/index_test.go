package keyindex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
)

// fakeIdentity builds a controllable identity with the given key ID, letting
// tests manufacture key ID collisions without real colliding keys. Distinct
// seeds produce distinct fingerprints that all map to the same key ID.
func fakeIdentity(t *testing.T, version int, keyID uint64, seed byte) KeyIdentity {
	t.Helper()
	length, err := fingerprintLength(version)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := make([]byte, length)
	for i := range fingerprint {
		fingerprint[i] = seed
	}
	if version == 4 {
		binary.BigEndian.PutUint64(fingerprint[length-8:], keyID)
	} else {
		binary.BigEndian.PutUint64(fingerprint[:8], keyID)
	}
	return KeyIdentity{Version: version, Fingerprint: fingerprint, KeyID: keyID}
}

func TestIndexKeyIDOutcomes(t *testing.T) {
	ix := NewIndex()
	snap := ix.Snapshot()
	if res := snap.ByKeyID(42); res.Status != Missing {
		t.Fatalf("empty index: got %v, want missing", res.Status)
	}

	only := ix.addIdentity(fakeIdentity(t, 4, 42, 0x0A), nil, false, "keyring-a")
	snap = ix.Snapshot()
	res := snap.ByKeyID(42)
	if res.Status != Unique || res.Record != only {
		t.Fatalf("single key: got %v, want unique", res.Status)
	}

	// Two different full fingerprints sharing one key ID must both be kept.
	other := ix.addIdentity(fakeIdentity(t, 4, 42, 0x0B), nil, false, "keyring-b")
	snap = ix.Snapshot()
	res = snap.ByKeyID(42)
	if res.Status != Ambiguous {
		t.Fatalf("colliding key ids: got %v, want ambiguous", res.Status)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(res.Candidates))
	}
	seen := map[*Record]bool{res.Candidates[0]: true, res.Candidates[1]: true}
	if !seen[only] || !seen[other] {
		t.Error("collision candidates do not include both imported keys")
	}

	// Exact fingerprint lookups still resolve each key uniquely.
	for _, record := range []*Record{only, other} {
		res, err := snap.ByFingerprint(record.Identity.Version, record.Identity.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != Unique || res.Record != record {
			t.Errorf("fingerprint lookup: got %v, want unique", res.Status)
		}
	}
}

func TestIndexDuplicateImportMergesSources(t *testing.T) {
	ix := NewIndex()
	identity := fakeIdentity(t, 6, 7, 0x01)
	first := ix.addIdentity(identity, nil, false, "keyring-a")
	if sources := first.Sources(); len(sources) != 1 || sources[0] != "keyring-a" {
		t.Fatalf("sources %v, want [keyring-a]", sources)
	}
	again := ix.addIdentity(identity, nil, false, "keyring-b")
	if ix.Snapshot().Len() != 1 {
		t.Fatalf("duplicate import created a second record")
	}
	sources := again.Sources()
	if len(sources) != 2 || sources[0] != "keyring-a" || sources[1] != "keyring-b" {
		t.Errorf("sources %v, want [keyring-a keyring-b]", sources)
	}
	// Re-importing an already known source is a no-op.
	ix.addIdentity(identity, nil, false, "keyring-a")
	if sources := ix.Snapshot().ByKeyID(7).Record.Sources(); len(sources) != 2 {
		t.Errorf("re-import changed sources: %v", sources)
	}
	// The key ID bucket must still hold exactly one record.
	if res := ix.Snapshot().ByKeyID(7); res.Status != Unique {
		t.Errorf("after duplicate import: got %v, want unique", res.Status)
	}
}

func TestIndexRejectsForgedCachedFields(t *testing.T) {
	ix := NewIndex()
	entity := readSampleEntity(t, keySamples[1].path)
	pk := entity.PrimaryKey
	pk.Fingerprint = append([]byte(nil), pk.Fingerprint...)
	pk.Fingerprint[0] ^= 0xFF
	if _, err := ix.Add(pk, "forged"); err == nil {
		t.Error("Add accepted a key whose cached fingerprint was forged")
	}
	if ix.Snapshot().Len() != 0 {
		t.Error("forged key was indexed")
	}
}

func TestSnapshotIsStableAcrossImports(t *testing.T) {
	ix := NewIndex()
	first := ix.addIdentity(fakeIdentity(t, 4, 99, 0x01), nil, false, "a")
	snap := ix.Snapshot()
	before := snap.ByKeyID(99)
	if before.Status != Unique {
		t.Fatalf("setup: got %v, want unique", before.Status)
	}

	// Later imports, including one colliding on the same key ID and a
	// duplicate of the first key, must not change the old snapshot.
	ix.addIdentity(fakeIdentity(t, 4, 99, 0x02), nil, false, "b")
	ix.addIdentity(fakeIdentity(t, 4, 99, 0x01), nil, false, "c")

	after := snap.ByKeyID(99)
	if after.Status != Unique || after.Record != first {
		t.Errorf("snapshot changed after imports: got %v", after.Status)
	}
	if sources := after.Record.Sources(); len(sources) != 1 || sources[0] != "a" {
		t.Errorf("snapshot record sources changed: %v", sources)
	}
	if snap.Len() != 1 {
		t.Errorf("snapshot length changed: %d", snap.Len())
	}

	fresh := ix.Snapshot()
	if res := fresh.ByKeyID(99); res.Status != Ambiguous || len(res.Candidates) != 2 {
		t.Errorf("fresh snapshot: got %v with %d candidates, want ambiguous with 2",
			res.Status, len(res.Candidates))
	}
	if sources := fresh.ByKeyID(99).Candidates[0].Sources(); len(sources) != 2 {
		t.Errorf("fresh snapshot did not observe merged sources: %v", sources)
	}
}

func TestSnapshotConcurrentQueries(t *testing.T) {
	ix := NewIndex()
	const keys = 64
	for i := 0; i < keys; i++ {
		// Deliberately reuse a small set of key IDs to create ambiguity.
		ix.addIdentity(fakeIdentity(t, 6, uint64(i%8), byte(i)), nil, false, fmt.Sprintf("src-%d", i))
	}
	snap := ix.Snapshot()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		// Concurrent imports must not disturb in-flight queries.
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				ix.addIdentity(fakeIdentity(t, 6, uint64(i%8), byte(0x80+i%64)), nil, false, "late")
			}
		}
	}()
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				res := snap.ByKeyID(uint64(i % 8))
				if res.Status != Ambiguous || len(res.Candidates) != keys/8 {
					t.Errorf("snapshot query returned %v with %d candidates", res.Status, len(res.Candidates))
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
}

func TestByFingerprintValidatesInput(t *testing.T) {
	snap := NewIndex().Snapshot()
	if _, err := snap.ByFingerprint(3, bytes.Repeat([]byte{1}, 20)); err == nil {
		t.Error("unsupported version accepted")
	}
	if _, err := snap.ByFingerprint(4, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Error("v4 query with v6-length fingerprint accepted")
	}
	if _, err := snap.ByFingerprint(6, bytes.Repeat([]byte{1}, 20)); err == nil {
		t.Error("v6 query with v4-length fingerprint accepted")
	}
	res, err := snap.ByFingerprint(4, bytes.Repeat([]byte{1}, 20))
	if err != nil || res.Status != Missing {
		t.Errorf("valid query on empty index: got %v, %v", res.Status, err)
	}
}
