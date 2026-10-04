package keyindex

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// keySamples are repository key samples with their known real fingerprints
// (primary key first, then subkeys), as pinned in openpgp/read_pqc_test.go.
var keySamples = []struct {
	path         string
	version      int
	fingerprints []string
}{
	{
		path:    "../test_data/pqc/v6-mldsa-65-sample-pk.asc",
		version: 6,
		fingerprints: []string{
			"a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242f",
			"7dae8fbce23022607167af72a002e774e0ca379a2d7ae072384e1e8fde3265e4",
		},
	},
	{
		path:    "../test_data/pqc/v4-eddsa-sample-pk.asc",
		version: 4,
		fingerprints: []string{
			"342e5db2de345215cb2c944f7102ffed3b9cf12d",
			"e51dbfea51936988b5428fffa4f95f985ed61a51",
		},
	},
}

func readSampleEntity(t *testing.T, path string) *openpgp.Entity {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(entities) != 1 {
		t.Fatalf("%s: expected 1 entity, got %d", path, len(entities))
	}
	return entities[0]
}

// allPublicKeys returns the entity's primary key followed by its subkeys.
func allPublicKeys(entity *openpgp.Entity) []*packet.PublicKey {
	keys := []*packet.PublicKey{entity.PrimaryKey}
	for i := range entity.Subkeys {
		keys = append(keys, entity.Subkeys[i].PublicKey)
	}
	return keys
}

func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
