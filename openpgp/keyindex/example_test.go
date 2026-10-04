package keyindex_test

import (
	"bytes"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/keyindex"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func Example() {
	// In a real tool this entity would come from an imported key package.
	entity, err := openpgp.NewEntity("Offline Signer", "", "signer@example.com", nil)
	if err != nil {
		fmt.Println("generate:", err)
		return
	}

	ix := keyindex.New()
	if err := ix.AddEntity(entity, "signer-package.asc"); err != nil {
		fmt.Println("import:", err)
		return
	}

	// Produce a detached signature over a message.
	payload := []byte("payload")
	var signature bytes.Buffer
	if err := openpgp.DetachSign(&signature, entity, bytes.NewReader(payload), nil); err != nil {
		fmt.Println("sign:", err)
		return
	}

	// Parse the signature packet and derive an issuer query. A real verifier
	// would read the signature from a file or armor.
	p, err := packet.NewReader(&signature).Next()
	if err != nil {
		fmt.Println("parse sig:", err)
		return
	}
	sig := p.(*packet.Signature)

	query, err := keyindex.IssuerQueryFromSignature(sig)
	if err != nil {
		fmt.Println("issuer query:", err)
		return
	}

	// Resolve against an immutable snapshot. Ambiguity is never hidden.
	result, err := ix.Snapshot().ResolveIssuer(query)
	if err != nil {
		fmt.Println("resolve:", err)
		return
	}
	signer, err := result.Unique()
	if err != nil {
		// result.Status == keyindex.LookupAmbiguous: demand a full fingerprint.
		fmt.Println("ambiguous:", err)
		return
	}

	fmt.Printf("located v%d key with %d-byte fingerprint; trust must still be established separately\n",
		signer.Identity.Version, len(signer.Identity.Fingerprint))
	// Output: located v4 key with 20-byte fingerprint; trust must still be established separately
}
