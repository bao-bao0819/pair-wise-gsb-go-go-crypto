package negotiate

import (
	"reflect"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func modernSender() SenderCapabilities {
	return SenderCapabilities{
		KeyVersions:     []int{4, 6},
		MessageVersions: []MessageVersion{MessageVersionSEIPDv2, MessageVersionSEIPDv1},
		Symmetric:       []packet.CipherFunction{packet.CipherAES256, packet.CipherAES128},
		Compression:     []packet.CompressionAlgo{packet.CompressionNone, packet.CompressionZLIB},
		AEAD: []packet.CipherSuite{
			{Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB},
			{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB},
			{Cipher: packet.CipherAES256, Mode: packet.AEADModeEAX},
			{Cipher: packet.CipherAES128, Mode: packet.AEADModeEAX},
		},
	}
}

func v6Recipient(id string) RecipientProfile {
	return RecipientProfile{
		ID:              id,
		KeyVersions:     []int{6},
		MessageVersions: []MessageVersion{MessageVersionSEIPDv2},
		Symmetric:       []packet.CipherFunction{packet.CipherAES256, packet.CipherAES128},
		Compression:     []packet.CompressionAlgo{packet.CompressionNone},
		AEAD: []packet.CipherSuite{
			{Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB},
			{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB},
		},
	}
}

func exclusionFor(result Result, candidate Candidate) *Exclusion {
	for i := range result.Excluded {
		if result.Excluded[i].Candidate == candidate {
			return &result.Excluded[i]
		}
	}
	return nil
}

func hasReason(exclusion *Exclusion, party, detail string) bool {
	if exclusion == nil {
		return false
	}
	for _, reason := range exclusion.Reasons {
		if reason.Party == party && reason.Detail == detail {
			return true
		}
	}
	return false
}

func TestSenderPriorityRanksCandidates(t *testing.T) {
	result := Negotiate(modernSender(), []RecipientProfile{v6Recipient("a")}, Policy{}, RFC9580Baseline())
	best, ok := result.Best()
	if !ok {
		t.Fatal("expected at least one feasible candidate")
	}
	want := Candidate{
		Version:     MessageVersionSEIPDv2,
		Cipher:      packet.CipherAES256,
		Mode:        packet.AEADModeOCB,
		Compression: packet.CompressionNone,
	}
	if best != want {
		t.Errorf("best candidate = %v, want %v", best, want)
	}
	// The recipient does not accept ZLIB, so every ZLIB combination must be
	// excluded with a reason naming the recipient.
	zlibCandidate := Candidate{Version: MessageVersionSEIPDv2, Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB, Compression: packet.CompressionZLIB}
	exclusion := exclusionFor(result, zlibCandidate)
	if !hasReason(exclusion, "recipient:a", "compression algorithm not supported") {
		t.Errorf("expected recipient:a compression exclusion for %v, got %+v", zlibCandidate, result.Excluded)
	}
}

func TestEmptyIntersectionDiagnostics(t *testing.T) {
	sender := modernSender()
	sender.MessageVersions = []MessageVersion{MessageVersionSEIPDv1}
	sender.Symmetric = []packet.CipherFunction{packet.CipherAES128, packet.CipherAES256}
	sender.Compression = []packet.CompressionAlgo{packet.CompressionNone}

	alice := RecipientProfile{
		ID:              "alice",
		KeyVersions:     []int{4},
		MessageVersions: []MessageVersion{MessageVersionSEIPDv1},
		Symmetric:       []packet.CipherFunction{packet.CipherAES128},
		Compression:     []packet.CompressionAlgo{packet.CompressionNone},
	}
	bob := alice
	bob.ID = "bob"
	bob.Symmetric = []packet.CipherFunction{packet.CipherAES256}

	result := Negotiate(sender, []RecipientProfile{alice, bob}, Policy{}, RFC4880Baseline())
	if len(result.Candidates) != 0 {
		t.Fatalf("expected empty intersection, got %v", result.Candidates)
	}
	aes128 := Candidate{Version: MessageVersionSEIPDv1, Cipher: packet.CipherAES128, Compression: packet.CompressionNone}
	aes256 := Candidate{Version: MessageVersionSEIPDv1, Cipher: packet.CipherAES256, Compression: packet.CompressionNone}
	if !hasReason(exclusionFor(result, aes128), "recipient:bob", "symmetric algorithm not supported") {
		t.Errorf("expected aes128 excluded by bob, got %+v", exclusionFor(result, aes128))
	}
	if !hasReason(exclusionFor(result, aes256), "recipient:alice", "symmetric algorithm not supported") {
		t.Errorf("expected aes256 excluded by alice, got %+v", exclusionFor(result, aes256))
	}

	// Reversing recipient order must not change the outcome.
	reversed := Negotiate(sender, []RecipientProfile{bob, alice}, Policy{}, RFC4880Baseline())
	if !reflect.DeepEqual(result, reversed) {
		t.Errorf("recipient order changed the result:\n%+v\nvs\n%+v", result, reversed)
	}
}

func TestAEADCrossCombinationTrap(t *testing.T) {
	// Each recipient supports both ciphers and both modes individually, but
	// their supported cipher/mode pairs do not overlap: a negotiator that
	// intersects ciphers and modes independently would wrongly conclude that
	// e.g. AES256+EAX is fine.
	alice := v6Recipient("alice")
	alice.AEAD = []packet.CipherSuite{
		{Cipher: packet.CipherAES128, Mode: packet.AEADModeEAX},
		{Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB},
	}
	bob := v6Recipient("bob")
	bob.AEAD = []packet.CipherSuite{
		{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB},
		{Cipher: packet.CipherAES256, Mode: packet.AEADModeEAX},
	}

	result := Negotiate(modernSender(), []RecipientProfile{alice, bob}, Policy{}, RFC9580Baseline())
	for _, candidate := range result.Candidates {
		if candidate.Version == MessageVersionSEIPDv2 {
			t.Errorf("unexpected feasible SEIPDv2 candidate %v", candidate)
		}
	}
	trap := Candidate{Version: MessageVersionSEIPDv2, Cipher: packet.CipherAES256, Mode: packet.AEADModeEAX, Compression: packet.CompressionNone}
	exclusion := exclusionFor(result, trap)
	if !hasReason(exclusion, "recipient:alice", "AEAD cipher/mode pair not supported") {
		t.Errorf("expected trap pair excluded by alice, got %+v", exclusion)
	}
	otherTrap := Candidate{Version: MessageVersionSEIPDv2, Cipher: packet.CipherAES128, Mode: packet.AEADModeEAX, Compression: packet.CompressionNone}
	if !hasReason(exclusionFor(result, otherTrap), "recipient:bob", "AEAD cipher/mode pair not supported") {
		t.Errorf("expected trap pair excluded by bob, got %+v", exclusionFor(result, otherTrap))
	}
}

func TestLegacyVersionParticipant(t *testing.T) {
	modern := v6Recipient("modern")
	modern.MessageVersions = []MessageVersion{MessageVersionSEIPDv2, MessageVersionSEIPDv1}
	legacy := RecipientProfile{
		ID:              "legacy",
		KeyVersions:     []int{4},
		MessageVersions: []MessageVersion{MessageVersionSEIPDv1},
		Symmetric:       []packet.CipherFunction{packet.CipherAES128, packet.Cipher3DES},
		Compression:     []packet.CompressionAlgo{packet.CompressionNone},
	}
	result := Negotiate(modernSender(), []RecipientProfile{modern, legacy}, Policy{}, RFC9580Baseline())
	best, ok := result.Best()
	if !ok {
		t.Fatalf("expected a SEIPDv1 fallback candidate, exclusions: %+v", result.Excluded)
	}
	if best.Version != MessageVersionSEIPDv1 || best.Cipher != packet.CipherAES128 {
		t.Errorf("best = %v, want SEIPDv1 with AES128", best)
	}
	// Every SEIPDv2 candidate must be excluded by the legacy recipient.
	v2 := Candidate{Version: MessageVersionSEIPDv2, Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB, Compression: packet.CompressionNone}
	if !hasReason(exclusionFor(result, v2), "recipient:legacy", "message version not supported") {
		t.Errorf("expected SEIPDv2 excluded by legacy recipient, got %+v", exclusionFor(result, v2))
	}
}

func TestDuplicateRecipientsDoNotChangeResult(t *testing.T) {
	sender := modernSender()
	recipients := []RecipientProfile{v6Recipient("a"), v6Recipient("b")}
	duplicated := []RecipientProfile{v6Recipient("b"), v6Recipient("a"), v6Recipient("b"), v6Recipient("a")}

	single := Negotiate(sender, recipients, Policy{}, RFC9580Baseline())
	double := Negotiate(sender, duplicated, Policy{}, RFC9580Baseline())
	if !reflect.DeepEqual(single, double) {
		t.Errorf("duplicate recipients changed the result:\n%+v\nvs\n%+v", single, double)
	}
}

func TestUnknownAlgorithmIDsAreUnsupported(t *testing.T) {
	sender := modernSender()
	sender.Symmetric = append(sender.Symmetric, packet.CipherFunction(200))
	sender.Compression = append(sender.Compression, packet.CompressionAlgo(200))
	sender.MessageVersions = append(sender.MessageVersions, MessageVersion(99))
	sender.KeyVersions = append(sender.KeyVersions, 99)
	sender.AEAD = append(sender.AEAD,
		packet.CipherSuite{Cipher: packet.CipherFunction(200), Mode: packet.AEADModeOCB},
		packet.CipherSuite{Cipher: packet.CipherAES128, Mode: packet.AEADMode(200)},
	)

	recipient := v6Recipient("a")
	recipient.Symmetric = []packet.CipherFunction{packet.CipherFunction(200)}
	recipient.KeyVersions = []int{99}

	result := Negotiate(sender, []RecipientProfile{recipient}, Policy{}, RFC9580Baseline())
	for _, candidate := range result.Candidates {
		if candidate.Cipher == packet.CipherFunction(200) || candidate.Mode == packet.AEADMode(200) ||
			candidate.Compression == packet.CompressionAlgo(200) || candidate.Version == MessageVersion(99) {
			t.Errorf("unknown algorithm ID negotiated: %v", candidate)
		}
	}
	// The recipient's unknown key version must not count as support.
	v2 := Candidate{Version: MessageVersionSEIPDv2, Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB, Compression: packet.CompressionNone}
	if !hasReason(exclusionFor(result, v2), "recipient:a", "no common key version") {
		t.Errorf("expected unknown key version to be treated as unsupported, got %+v", exclusionFor(result, v2))
	}
}

func TestNoSilentDowngradeToForbiddenAlgorithm(t *testing.T) {
	sender := modernSender()
	sender.MessageVersions = []MessageVersion{MessageVersionSEIPDv1}
	sender.Symmetric = []packet.CipherFunction{packet.CipherAES128, packet.Cipher3DES}
	sender.Compression = []packet.CompressionAlgo{packet.CompressionNone}

	policy := Policy{ForbiddenCiphers: []packet.CipherFunction{packet.Cipher3DES}}

	// Recipient with missing preferences: the RFC 4880 baseline implies 3DES
	// only, which the policy forbids, so nothing may be negotiated.
	legacy := RecipientProfile{ID: "legacy", KeyVersions: []int{4}}
	policy.ApplyImplicitPreferences = true
	result := Negotiate(sender, []RecipientProfile{legacy}, policy, RFC4880Baseline())
	if len(result.Candidates) != 0 {
		t.Fatalf("expected no candidates, got %v", result.Candidates)
	}
	forbidden := Candidate{Version: MessageVersionSEIPDv1, Cipher: packet.Cipher3DES, Compression: packet.CompressionNone}
	if !hasReason(exclusionFor(result, forbidden), "policy", "cipher 2 forbidden by policy") {
		t.Errorf("expected 3DES excluded by policy, got %+v", exclusionFor(result, forbidden))
	}
	aes128 := Candidate{Version: MessageVersionSEIPDv1, Cipher: packet.CipherAES128, Compression: packet.CompressionNone}
	if !hasReason(exclusionFor(result, aes128), "recipient:legacy", "symmetric algorithm not supported") {
		t.Errorf("expected AES128 excluded by legacy implicit preferences, got %+v", exclusionFor(result, aes128))
	}

	// Without implicit preferences, a missing list means no support at all.
	policy.ApplyImplicitPreferences = false
	result = Negotiate(sender, []RecipientProfile{legacy}, policy, RFC4880Baseline())
	if len(result.Candidates) != 0 {
		t.Fatalf("expected no candidates without implicit preferences, got %v", result.Candidates)
	}
}

func TestRequireAEADPolicy(t *testing.T) {
	legacy := RecipientProfile{
		ID:              "legacy",
		KeyVersions:     []int{4},
		MessageVersions: []MessageVersion{MessageVersionSEIPDv1},
		Symmetric:       []packet.CipherFunction{packet.CipherAES128},
		Compression:     []packet.CompressionAlgo{packet.CompressionNone},
	}
	policy := Policy{RequireAEAD: true}
	result := Negotiate(modernSender(), []RecipientProfile{legacy}, policy, RFC9580Baseline())
	if len(result.Candidates) != 0 {
		t.Fatalf("expected no candidates, got %v", result.Candidates)
	}
	v1 := Candidate{Version: MessageVersionSEIPDv1, Cipher: packet.CipherAES128, Compression: packet.CompressionNone}
	if !hasReason(exclusionFor(result, v1), "policy", "policy requires AEAD (SEIPDv2)") {
		t.Errorf("expected SEIPDv1 excluded by policy, got %+v", exclusionFor(result, v1))
	}
}
