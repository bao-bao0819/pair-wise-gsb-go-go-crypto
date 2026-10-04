package negotiate

import (
	"reflect"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func testPolicy() Policy {
	return Policy{Fallback: DefaultBaseline()}
}

func modernRecipient(name string) Recipient {
	return Recipient{
		Name:         name,
		Versions:     []MessageVersion{MessageVersionSEIPDv1, MessageVersionSEIPDv2},
		Ciphers:      []packet.CipherFunction{packet.CipherAES128, packet.CipherAES256},
		Compressions: []packet.CompressionAlgo{packet.CompressionNone, packet.CompressionZLIB},
		AEAD: []packet.CipherSuite{
			{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB},
			{Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB},
		},
	}
}

func testSender() Sender {
	return Sender{
		Versions:     []MessageVersion{MessageVersionSEIPDv2, MessageVersionSEIPDv1},
		Ciphers:      []packet.CipherFunction{packet.CipherAES256, packet.CipherAES128},
		Compressions: []packet.CompressionAlgo{packet.CompressionZLIB, packet.CompressionNone, packet.CompressionZIP},
		AEAD: []packet.CipherSuite{
			{Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB},
			{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB},
		},
	}
}

func TestNegotiateSelectsSenderTopChoice(t *testing.T) {
	result := Negotiate([]Recipient{modernRecipient("alice"), modernRecipient("bob")}, testSender(), testPolicy())
	want := Candidate{
		Version:     MessageVersionSEIPDv2,
		Cipher:      packet.CipherAES256,
		Compression: packet.CompressionZLIB,
		AEADMode:    packet.AEADModeOCB,
	}
	if result.Selected == nil || *result.Selected != want {
		t.Fatalf("Selected = %+v, want %+v", result.Selected, want)
	}
	if len(result.Rejected) == 0 {
		t.Fatal("expected some candidates to be rejected")
	}
}

func TestNegotiateEmptyIntersectionDiagnostics(t *testing.T) {
	alice := modernRecipient("alice")
	bob := modernRecipient("bob")
	bob.Ciphers = []packet.CipherFunction{packet.CipherCAST5}
	bob.Compressions = []packet.CompressionAlgo{packet.CompressionZIP}
	bob.AEAD = []packet.CipherSuite{{Cipher: packet.CipherCAST5, Mode: packet.AEADModeEAX}}

	result := Negotiate([]Recipient{alice, bob}, testSender(), testPolicy())
	if result.Selected != nil {
		t.Fatalf("Selected = %+v, want nil", result.Selected)
	}
	if len(result.Feasible) != 0 {
		t.Fatalf("Feasible = %+v, want empty", result.Feasible)
	}
	if len(result.Rejected) == 0 {
		t.Fatal("expected rejection diagnostics for every candidate")
	}
	for _, rejection := range result.Rejected {
		if len(rejection.Reasons) == 0 {
			t.Errorf("candidate %+v rejected without reasons", rejection.Candidate)
		}
		for _, reason := range rejection.Reasons {
			if reason.Source == "" || reason.Detail == "" {
				t.Errorf("candidate %+v has incomplete reason %+v", rejection.Candidate, reason)
			}
		}
	}
	// The SEIPDv2 candidates must name bob, who supports none of the
	// sender's AEAD suites.
	first := result.Rejected[0]
	foundBob := false
	for _, reason := range first.Reasons {
		if reason.Source == "bob" {
			foundBob = true
		}
	}
	if !foundBob {
		t.Errorf("expected bob among excluders of %+v, got %+v", first.Candidate, first.Reasons)
	}
}

func TestNegotiateAEADCrossCombinationTrap(t *testing.T) {
	// carol supports (AES-128, OCB) and (AES-256, GCM) only. A negotiator
	// picking cipher and mode independently would combine AES-256 with
	// OCB and produce an invalid message for carol.
	carol := Recipient{
		Name:         "carol",
		Versions:     []MessageVersion{MessageVersionSEIPDv2},
		Compressions: []packet.CompressionAlgo{packet.CompressionNone},
		AEAD: []packet.CipherSuite{
			{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB},
			{Cipher: packet.CipherAES256, Mode: packet.AEADModeGCM},
		},
	}
	sender := Sender{
		Versions:     []MessageVersion{MessageVersionSEIPDv2},
		Compressions: []packet.CompressionAlgo{packet.CompressionNone},
		AEAD: []packet.CipherSuite{
			{Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB},
			{Cipher: packet.CipherAES256, Mode: packet.AEADModeGCM},
			{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB},
		},
	}
	result := Negotiate([]Recipient{carol}, sender, testPolicy())
	want := Candidate{
		Version:     MessageVersionSEIPDv2,
		Cipher:      packet.CipherAES256,
		Compression: packet.CompressionNone,
		AEADMode:    packet.AEADModeGCM,
	}
	if result.Selected == nil || *result.Selected != want {
		t.Fatalf("Selected = %+v, want %+v", result.Selected, want)
	}
	for _, feasible := range result.Feasible {
		supported := false
		for _, suite := range carol.AEAD {
			if suite.Cipher == feasible.Cipher && suite.Mode == feasible.AEADMode {
				supported = true
			}
		}
		if !supported {
			t.Errorf("feasible candidate %+v combines cipher and mode carol never paired", feasible)
		}
	}
}

func TestNegotiateLegacyVersionParticipant(t *testing.T) {
	legacy := Recipient{
		Name:         "legacy",
		Versions:     []MessageVersion{MessageVersionSEIPDv1},
		Ciphers:      []packet.CipherFunction{packet.CipherAES128},
		Compressions: []packet.CompressionAlgo{packet.CompressionNone},
	}
	result := Negotiate([]Recipient{modernRecipient("alice"), legacy}, testSender(), testPolicy())
	want := Candidate{
		Version:     MessageVersionSEIPDv1,
		Cipher:      packet.CipherAES128,
		Compression: packet.CompressionNone,
	}
	if result.Selected == nil || *result.Selected != want {
		t.Fatalf("Selected = %+v, want %+v", result.Selected, want)
	}
	for _, feasible := range result.Feasible {
		if feasible.Version != MessageVersionSEIPDv1 {
			t.Errorf("feasible candidate %+v uses a version the legacy recipient cannot parse", feasible)
		}
	}
	// Every SEIPDv2 candidate must be rejected with legacy as a reason.
	for _, rejection := range result.Rejected {
		if rejection.Candidate.Version != MessageVersionSEIPDv2 {
			continue
		}
		found := false
		for _, reason := range rejection.Reasons {
			if reason.Source == "legacy" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected legacy among excluders of %+v, got %+v", rejection.Candidate, rejection.Reasons)
		}
	}
}

func TestNegotiateDuplicateRecipientsAndOrder(t *testing.T) {
	alice := modernRecipient("alice")
	bob := modernRecipient("bob")
	bob.Ciphers = []packet.CipherFunction{packet.CipherAES128}
	bob.AEAD = []packet.CipherSuite{{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB}}
	sender := testSender()
	policy := testPolicy()

	base := Negotiate([]Recipient{alice, bob}, sender, policy)
	duplicated := Negotiate([]Recipient{bob, alice, bob, alice, bob}, sender, policy)
	reversed := Negotiate([]Recipient{bob, alice}, sender, policy)

	if !reflect.DeepEqual(base, duplicated) {
		t.Errorf("duplicate recipients changed the outcome:\nbase: %+v\nduplicated: %+v", base, duplicated)
	}
	if !reflect.DeepEqual(base, reversed) {
		t.Errorf("recipient order changed the outcome:\nbase: %+v\nreversed: %+v", base, reversed)
	}
}

func TestNegotiateNoSilentDowngrade(t *testing.T) {
	// The only common cipher is CAST5, but policy forbids it: the result
	// must be empty rather than downgrading.
	carol := Recipient{
		Name:         "carol",
		Versions:     []MessageVersion{MessageVersionSEIPDv1},
		Ciphers:      []packet.CipherFunction{packet.CipherCAST5},
		Compressions: []packet.CompressionAlgo{packet.CompressionNone},
	}
	sender := Sender{
		Versions:     []MessageVersion{MessageVersionSEIPDv1},
		Ciphers:      []packet.CipherFunction{packet.CipherCAST5},
		Compressions: []packet.CompressionAlgo{packet.CompressionNone},
	}
	policy := testPolicy()
	policy.ForbiddenCiphers = map[packet.CipherFunction]bool{packet.CipherCAST5: true}

	result := Negotiate([]Recipient{carol}, sender, policy)
	if result.Selected != nil || len(result.Feasible) != 0 {
		t.Fatalf("forbidden cipher was selected: %+v", result.Feasible)
	}
	if len(result.Rejected) != 1 {
		t.Fatalf("expected exactly one rejected candidate, got %+v", result.Rejected)
	}
	reasons := result.Rejected[0].Reasons
	if len(reasons) != 1 || reasons[0].Source != sourcePolicy {
		t.Errorf("expected a single policy reason, got %+v", reasons)
	}
}

func TestNegotiateMissingPreferencesUseBaseline(t *testing.T) {
	// A recipient that publishes no preferences is assumed to support the
	// protocol baseline only: SEIPDv1, TripleDES, no compression.
	silent := Recipient{Name: "silent"}
	sender := Sender{
		Versions:     []MessageVersion{MessageVersionSEIPDv1},
		Ciphers:      []packet.CipherFunction{packet.CipherAES128, packet.Cipher3DES},
		Compressions: []packet.CompressionAlgo{packet.CompressionNone},
	}
	result := Negotiate([]Recipient{silent}, sender, testPolicy())
	want := Candidate{
		Version:     MessageVersionSEIPDv1,
		Cipher:      packet.Cipher3DES,
		Compression: packet.CompressionNone,
	}
	if result.Selected == nil || *result.Selected != want {
		t.Fatalf("Selected = %+v, want baseline %+v", result.Selected, want)
	}
}

func TestNegotiateUnknownAlgorithmIDs(t *testing.T) {
	// Unknown algorithm identifiers must be treated as unsupported, not
	// cause a panic.
	weird := Recipient{
		Name:         "weird",
		Versions:     []MessageVersion{MessageVersionSEIPDv1, MessageVersion(42)},
		Ciphers:      []packet.CipherFunction{packet.CipherAES128, packet.CipherFunction(200)},
		Compressions: []packet.CompressionAlgo{packet.CompressionNone, packet.CompressionAlgo(99)},
		AEAD: []packet.CipherSuite{
			{Cipher: packet.CipherAES128, Mode: packet.AEADMode(77)},
		},
	}
	sender := Sender{
		Versions:     []MessageVersion{MessageVersion(42), MessageVersionSEIPDv1},
		Ciphers:      []packet.CipherFunction{packet.CipherFunction(200), packet.CipherAES128},
		Compressions: []packet.CompressionAlgo{packet.CompressionAlgo(99), packet.CompressionNone},
		AEAD:         []packet.CipherSuite{{Cipher: packet.CipherAES128, Mode: packet.AEADMode(77)}},
	}
	result := Negotiate([]Recipient{weird}, sender, testPolicy())
	want := Candidate{
		Version:     MessageVersionSEIPDv1,
		Cipher:      packet.CipherAES128,
		Compression: packet.CompressionNone,
	}
	if result.Selected == nil || *result.Selected != want {
		t.Fatalf("Selected = %+v, want %+v", result.Selected, want)
	}
	for _, feasible := range result.Feasible {
		if feasible.Version == MessageVersion(42) || feasible.Cipher == packet.CipherFunction(200) ||
			feasible.Compression == packet.CompressionAlgo(99) || feasible.AEADMode == packet.AEADMode(77) {
			t.Errorf("unknown algorithm id survived negotiation: %+v", feasible)
		}
	}
}

func TestNegotiateRequireAEAD(t *testing.T) {
	policy := testPolicy()
	policy.RequireAEAD = true
	result := Negotiate([]Recipient{modernRecipient("alice")}, testSender(), policy)
	if result.Selected == nil || result.Selected.Version != MessageVersionSEIPDv2 {
		t.Fatalf("Selected = %+v, want an SEIPDv2 candidate", result.Selected)
	}
	for _, rejection := range result.Rejected {
		if rejection.Candidate.Version != MessageVersionSEIPDv1 {
			continue
		}
		found := false
		for _, reason := range rejection.Reasons {
			if reason.Source == sourcePolicy {
				found = true
			}
		}
		if !found {
			t.Errorf("expected policy reason for %+v, got %+v", rejection.Candidate, rejection.Reasons)
		}
	}
}
