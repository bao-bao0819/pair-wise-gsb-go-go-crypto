package keyindex

import (
	"bytes"
	"testing"
)

// TestRealKeySamples imports the repository's v4 and v6 sample keys and
// checks that every primary key and subkey can be found by its real,
// independently known fingerprint and by its derived key ID.
func TestRealKeySamples(t *testing.T) {
	ix := NewIndex()
	for _, sample := range keySamples {
		entity := readSampleEntity(t, sample.path)
		if err := ix.AddEntity(entity, sample.path); err != nil {
			t.Fatalf("%s: %v", sample.path, err)
		}
	}
	snap := ix.Snapshot()
	total := 0
	for _, sample := range keySamples {
		total += len(sample.fingerprints)
	}
	if snap.Len() != total {
		t.Fatalf("indexed %d keys, want %d", snap.Len(), total)
	}

	for _, sample := range keySamples {
		entity := readSampleEntity(t, sample.path)
		keys := allPublicKeys(entity)
		for i, pk := range keys {
			fingerprint := hexDecode(t, sample.fingerprints[i])
			res, err := snap.ByFingerprint(sample.version, fingerprint)
			if err != nil {
				t.Fatalf("%s key %d: %v", sample.path, i, err)
			}
			if res.Status != Unique {
				t.Fatalf("%s key %d: got %v, want unique", sample.path, i, res.Status)
			}
			if got := res.Record.Identity.Fingerprint; !bytes.Equal(got, fingerprint) {
				t.Errorf("%s key %d: record fingerprint %X, want %X", sample.path, i, got, fingerprint)
			}
			if !bytes.Equal(res.Record.Key.Fingerprint, pk.Fingerprint) {
				t.Errorf("%s key %d: lookup returned different key material", sample.path, i)
			}
			if res.Record.Subkey != pk.IsSubkey {
				t.Errorf("%s key %d: subkey flag %v, want %v", sample.path, i, res.Record.Subkey, pk.IsSubkey)
			}
			if sources := res.Record.Sources(); len(sources) != 1 || sources[0] != sample.path {
				t.Errorf("%s key %d: sources %v", sample.path, i, sources)
			}

			// The key ID derived from the real fingerprint must find the
			// same record (unambiguous within this key set).
			keyID, err := keyIDFromFingerprint(sample.version, fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if keyID != pk.KeyId {
				t.Errorf("%s key %d: derived key id %016X, want %016X", sample.path, i, keyID, pk.KeyId)
			}
			byID := snap.ByKeyID(keyID)
			if byID.Status != Unique ||
				!bytes.Equal(byID.Record.Identity.Fingerprint, fingerprint) {
				t.Errorf("%s key %d: key id lookup got %v, want unique", sample.path, i, byID.Status)
			}
		}
	}
}

// TestRealKeySamplesDuplicateImport re-imports the same key material from a
// second source and checks that records are merged, not duplicated.
func TestRealKeySamplesDuplicateImport(t *testing.T) {
	ix := NewIndex()
	entity := readSampleEntity(t, keySamples[0].path)
	if err := ix.AddEntity(entity, "first"); err != nil {
		t.Fatal(err)
	}
	if err := ix.AddEntity(entity, "second"); err != nil {
		t.Fatal(err)
	}
	snap := ix.Snapshot()
	if snap.Len() != len(keySamples[0].fingerprints) {
		t.Fatalf("duplicate import inflated the index to %d keys", snap.Len())
	}
	res, err := snap.ByFingerprint(keySamples[0].version, hexDecode(t, keySamples[0].fingerprints[0]))
	if err != nil {
		t.Fatal(err)
	}
	if sources := res.Record.Sources(); len(sources) != 2 || sources[0] != "first" || sources[1] != "second" {
		t.Errorf("sources %v, want [first second]", sources)
	}
}
