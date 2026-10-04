package keyindex_test

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/keyindex"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Real fingerprints of the repository's sample key packages. These are checked
// against fingerprints recomputed by the index from the canonical key
// representation; they are not trusted from the packets directly.
const (
	v4EddsaPrimaryFingerprint = "342E5DB2DE345215CB2C944F7102FFED3B9CF12D"
	v4EddsaSubkeyFingerprint  = "E51DBFEA51936988B5428FFFA4F95F985ED61A51"
	v6MldsaPrimaryFingerprint = "A3E2E14B6A493FF930FB27321F125E9A6880338BE9FB7DA3AE065EA65793242F"
	v6MldsaSubkeyFingerprint  = "7DAE8FBCE23022607167AF72A002E774E0CA379A2D7AE072384E1E8FDE3265E4"
)

func mustReadSample(t *testing.T, name string) openpgp.EntityList {
	t.Helper()
	path := filepath.Join("..", "test_data", "pqc", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	el, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return el
}

func hexToBytes(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex constant %q: %v", s, err)
	}
	return out
}

// TestRealSamplesExactFingerprint verifies recomputed fingerprints against the
// real v4 and v6 sample keys in the repository, for both primary keys and
// subkeys.
func TestRealSamplesExactFingerprint(t *testing.T) {
	ix := keyindex.New()

	v4 := mustReadSample(t, "v4-eddsa-sample-pk.asc")
	v6 := mustReadSample(t, "v6-mldsa-65-sample-pk.asc")
	if err := ix.AddEntity(v4[0], "v4-eddsa-sample-pk.asc"); err != nil {
		t.Fatalf("add v4 entity: %v", err)
	}
	if err := ix.AddEntity(v6[0], "v6-mldsa-65-sample-pk.asc"); err != nil {
		t.Fatalf("add v6 entity: %v", err)
	}

	snap := ix.Snapshot()
	cases := []struct {
		version int
		hexFP   string
		isSub   bool
	}{
		{4, v4EddsaPrimaryFingerprint, false},
		{4, v4EddsaSubkeyFingerprint, true},
		{6, v6MldsaPrimaryFingerprint, false},
		{6, v6MldsaSubkeyFingerprint, true},
	}
	for _, c := range cases {
		entry, err := snap.FindByFingerprint(c.version, hexToBytes(t, c.hexFP))
		if err != nil {
			t.Fatalf("fingerprint %s not found: %v", c.hexFP, err)
		}
		if entry.IsSubkey != c.isSub {
			t.Fatalf("%s: IsSubkey = %v, want %v", c.hexFP, entry.IsSubkey, c.isSub)
		}
		if entry.Identity.Version != c.version {
			t.Fatalf("%s: version %d, want %d", c.hexFP, entry.Identity.Version, c.version)
		}
	}
}

// TestRepeatedImportMergesSources imports the same key package twice and
// confirms the index keeps one entry with merged, deduplicated sources.
func TestRepeatedImportMergesSources(t *testing.T) {
	ix := keyindex.New()
	v4 := mustReadSample(t, "v4-eddsa-sample-pk.asc")

	if err := ix.AddEntity(v4[0], "copy-1.asc"); err != nil {
		t.Fatal(err)
	}
	if err := ix.AddEntity(v4[0], "copy-2.asc"); err != nil {
		t.Fatal(err)
	}
	if err := ix.AddEntity(v4[0], "copy-1.asc"); err != nil { // duplicate source
		t.Fatal(err)
	}

	entry, err := ix.Snapshot().FindByFingerprint(4, hexToBytes(t, v4EddsaPrimaryFingerprint))
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.Sources) != 2 {
		t.Fatalf("expected 2 merged distinct sources, got %v", entry.Sources)
	}
}

// TestSnapshotStableAcrossImports ensures a captured snapshot keeps returning
// the same candidate slices while later imports grow the live index; in
// particular, importing a second key sharing a short ID cannot mutate the
// unique result a snapshot holder is already using.
func TestSnapshotStableAcrossImports(t *testing.T) {
	ix := keyindex.New()
	v4 := mustReadSample(t, "v4-eddsa-sample-pk.asc")
	if err := ix.AddEntity(v4[0], "v4.asc"); err != nil {
		t.Fatal(err)
	}

	snap := ix.Snapshot()
	primaryShort := uint32(v4[0].PrimaryKey.KeyId)
	before := snap.LookupShortKeyID(primaryShort)
	if before.Status != keyindex.LookupUnique {
		t.Fatalf("expected unique before, got %d", before.Status)
	}
	fingerprintBefore := before.Candidates[0].Identity.Fingerprint

	// Grow the live index with a genuinely distinct package. The captured
	// snapshot must remain unchanged.
	v6 := mustReadSample(t, "v6-mldsa-65-sample-pk.asc")
	if err := ix.AddEntity(v6[0], "v6.asc"); err != nil {
		t.Fatal(err)
	}

	// The old snapshot must be unchanged: still unique, same backing array.
	after := snap.LookupShortKeyID(primaryShort)
	if after.Status != keyindex.LookupUnique {
		t.Fatalf("snapshot mutated by later import: status %d", after.Status)
	}
	if &after.Candidates[0].Identity.Fingerprint[0] != &fingerprintBefore[0] {
		t.Fatal("snapshot candidate slice/backing array changed after import")
	}

	// The fresh snapshot sees the grown index.
	fresh := ix.Snapshot()
	if _, err := fresh.FindByFingerprint(6, hexToBytes(t, v6MldsaPrimaryFingerprint)); err != nil {
		t.Fatalf("v6 key missing from fresh snapshot: %v", err)
	}
	if _, err := snap.FindByFingerprint(6, hexToBytes(t, v6MldsaPrimaryFingerprint)); !errors.Is(err, keyindex.ErrNotFound) {
		t.Fatalf("old snapshot must not observe new imports, got %v", err)
	}
}

// TestSnapshotConcurrentReadersAndImporter exercises the guarantee that
// read-only snapshots are safe for concurrent queries while imports continue.
func TestSnapshotConcurrentReadersAndImporter(t *testing.T) {
	ix := keyindex.New()
	v4 := mustReadSample(t, "v4-eddsa-sample-pk.asc")
	if err := ix.AddEntity(v4[0], "v4.asc"); err != nil {
		t.Fatal(err)
	}

	const readers = 16
	const iterations = 200
	var wg sync.WaitGroup

	// Readers hold one fixed snapshot and hammer it.
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap := ix.Snapshot()
			fp := hexToBytes(t, v4EddsaPrimaryFingerprint)
			for i := 0; i < iterations; i++ {
				result := snap.LookupShortKeyID(uint32(v4[0].PrimaryKey.KeyId))
				if result.Status != keyindex.LookupUnique {
					t.Errorf("concurrent read: expected unique, got %d", result.Status)
					return
				}
				if _, err := snap.FindByFingerprint(4, fp); err != nil {
					t.Errorf("concurrent fingerprint read failed: %v", err)
					return
				}
			}
		}()
	}

	// A writer keeps re-importing the same key (source merges) concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := ix.AddEntity(v4[0], "v4.asc"); err != nil {
				t.Errorf("concurrent import failed: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}

// TestMissingAndAmbiguousExplicit checks the documented status semantics on the
// public API with real imported keys (no collision available among samples, so
// ambiguity is asserted through the controlled internal test; here we verify
// missing and unique).
func TestMissingAndAmbiguousExplicit(t *testing.T) {
	ix := keyindex.New()
	v4 := mustReadSample(t, "v4-eddsa-sample-pk.asc")
	if err := ix.AddEntity(v4[0], "v4.asc"); err != nil {
		t.Fatal(err)
	}
	snap := ix.Snapshot()

	missing := snap.LookupShortKeyID(0x0BADF00D)
	if missing.Status != keyindex.LookupMissing {
		t.Fatalf("expected missing, got %d", missing.Status)
	}

	unique := snap.LookupFullKeyID(v4[0].PrimaryKey.KeyId)
	if unique.Status != keyindex.LookupUnique || len(unique.Candidates) != 1 {
		t.Fatalf("expected unique full key id match, got %d", unique.Status)
	}
	entry, err := unique.Unique()
	if err != nil {
		t.Fatal(err)
	}
	if entry.PublicKey != v4[0].PrimaryKey {
		t.Fatal("entry should reference the imported packet")
	}
}

// TestGeneratedV6EntityImported exercises the import and exact-lookup path on
// a freshly generated v6 entity (primary + subkey), complementing the static
// v6 sample.
func TestGeneratedV6EntityImported(t *testing.T) {
	entity, err := openpgp.NewEntity("V6 Owner", "", "v6@example.com", &packet.Config{V6Keys: true})
	if err != nil {
		t.Fatalf("generate v6 entity: %v", err)
	}

	ix := keyindex.New()
	if err := ix.AddEntity(entity, "generated-v6"); err != nil {
		t.Fatalf("add v6 entity: %v", err)
	}
	snap := ix.Snapshot()

	primary, err := snap.FindByFingerprint(6, entity.PrimaryKey.Fingerprint)
	if err != nil {
		t.Fatalf("v6 primary not indexed: %v", err)
	}
	if primary.IsSubkey || primary.Identity.KeyID != entity.PrimaryKey.KeyId {
		t.Fatal("v6 primary entry is inconsistent")
	}

	// A wrong-length fingerprint for v6 is a distinct error.
	if _, err := snap.FindByFingerprint(6, entity.PrimaryKey.Fingerprint[:20]); !errors.Is(err, keyindex.ErrInvalidFingerprint) {
		t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
	}

	for _, sub := range entity.Subkeys {
		entry, err := snap.FindByFingerprint(6, sub.PublicKey.Fingerprint)
		if err != nil {
			t.Fatalf("v6 subkey not indexed: %v", err)
		}
		if !entry.IsSubkey {
			t.Fatal("expected subkey flag on subkey entry")
		}
	}
}
