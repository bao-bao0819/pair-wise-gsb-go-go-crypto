// Package negotiate implements pure, deterministic negotiation of OpenPGP
// message parameters for encrypting one message to a group of recipients.
//
// The negotiator only computes over descriptors supplied by the caller:
// recipient preferences are assumed to be already verified (e.g. taken from a
// valid self-signature), and no key server lookups or signature trust
// decisions are performed here.
package negotiate

import (
	"fmt"
	"sort"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// MessageVersion identifies the version of the symmetrically encrypted
// message format.
type MessageVersion int

const (
	// MessageVersionSEIPDv1 is the RFC 4880 SEIPD (MDC) message format.
	MessageVersionSEIPDv1 MessageVersion = 1
	// MessageVersionSEIPDv2 is the RFC 9580 SEIPD (AEAD) message format.
	MessageVersionSEIPDv2 MessageVersion = 2
)

// Candidate is one fully-specified combination of message parameters. AEAD
// ciphers and modes are always negotiated as a pair, never independently.
type Candidate struct {
	Version     MessageVersion
	Cipher      packet.CipherFunction
	Mode        packet.AEADMode // zero when Version is MessageVersionSEIPDv1
	Compression packet.CompressionAlgo
}

func (c Candidate) String() string {
	if c.Version == MessageVersionSEIPDv2 {
		return fmt.Sprintf("SEIPDv2/cipher=%d/mode=%d/compression=%d",
			byte(c.Cipher), byte(c.Mode), byte(c.Compression))
	}
	return fmt.Sprintf("SEIPDv1/cipher=%d/compression=%d",
		byte(c.Cipher), byte(c.Compression))
}

// RecipientProfile describes one recipient's verified preferences. A nil
// slice means the preference list is missing; how missing lists are treated
// is decided by Policy.ApplyImplicitPreferences. Unknown algorithm IDs are
// treated as unsupported and ignored.
type RecipientProfile struct {
	// ID is a stable identifier used in diagnostics.
	ID              string
	KeyVersions     []int
	MessageVersions []MessageVersion
	Symmetric       []packet.CipherFunction
	Compression     []packet.CompressionAlgo
	// AEAD lists the cipher/mode pairs the recipient can decrypt, used for
	// SEIPDv2 messages.
	AEAD []packet.CipherSuite
}

// SenderCapabilities describes what the sender can produce. The slices are
// the sender's explicit priority order: feasible candidates are ranked by
// them, most preferred first.
type SenderCapabilities struct {
	KeyVersions     []int
	MessageVersions []MessageVersion
	Symmetric       []packet.CipherFunction
	Compression     []packet.CompressionAlgo
	AEAD            []packet.CipherSuite
}

// Policy expresses application-level restrictions. It is kept separate from
// the protocol baseline: the baseline states what the protocol mandates,
// while the policy states what the application additionally forbids or
// requires. The negotiator never silently downgrades to an algorithm the
// policy forbids.
type Policy struct {
	ForbiddenCiphers     []packet.CipherFunction
	ForbiddenAEADModes   []packet.AEADMode
	ForbiddenCompression []packet.CompressionAlgo
	// AllowedMessageVersions restricts the usable message format versions.
	// Empty means every version the sender offers is acceptable.
	AllowedMessageVersions []MessageVersion
	// AllowedKeyVersions restricts the recipient key versions that may be
	// encrypted to. Empty means every key version the sender supports is
	// acceptable.
	AllowedKeyVersions []int
	// RequireAEAD forbids falling back to SEIPDv1 (non-AEAD) messages.
	RequireAEAD bool
	// ApplyImplicitPreferences controls the handling of missing (nil)
	// recipient preference lists: when true, the protocol baseline's implicit
	// preferences are assumed; when false, a missing list means the recipient
	// supports nothing in that dimension.
	ApplyImplicitPreferences bool
}

// ProtocolBaseline describes the capabilities and implicit preferences that
// the protocol itself mandates, independent of application policy.
type ProtocolBaseline struct {
	Name            string
	KeyVersions     []int
	MessageVersions []MessageVersion
	Symmetric       []packet.CipherFunction
	Compression     []packet.CompressionAlgo
	AEAD            []packet.CipherSuite
}

// RFC4880Baseline returns the mandatory-to-implement capabilities and
// implicit preferences of RFC 4880.
func RFC4880Baseline() ProtocolBaseline {
	return ProtocolBaseline{
		Name:            "RFC4880",
		KeyVersions:     []int{4},
		MessageVersions: []MessageVersion{MessageVersionSEIPDv1},
		Symmetric:       []packet.CipherFunction{packet.Cipher3DES},
		Compression:     []packet.CompressionAlgo{packet.CompressionNone},
	}
}

// RFC9580Baseline returns the mandatory-to-implement capabilities and
// implicit preferences of RFC 9580.
func RFC9580Baseline() ProtocolBaseline {
	return ProtocolBaseline{
		Name:            "RFC9580",
		KeyVersions:     []int{4, 6},
		MessageVersions: []MessageVersion{MessageVersionSEIPDv2, MessageVersionSEIPDv1},
		Symmetric:       []packet.CipherFunction{packet.CipherAES128},
		Compression:     []packet.CompressionAlgo{packet.CompressionNone},
		AEAD: []packet.CipherSuite{
			{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB},
		},
	}
}

// ExclusionReason records one party's reason for excluding a candidate.
type ExclusionReason struct {
	// Party is "policy" or "recipient:<id>".
	Party  string
	Detail string
}

// Exclusion records why a candidate is not feasible.
type Exclusion struct {
	Candidate Candidate
	Reasons   []ExclusionReason
}

// Result is the outcome of a negotiation.
type Result struct {
	// Candidates holds the feasible combinations, ranked by the sender's
	// explicit priority order, most preferred first.
	Candidates []Candidate
	// Excluded holds, in a stable order, every infeasible combination from
	// the sender's capability space together with who excluded it and why.
	Excluded []Exclusion
}

// Best returns the most preferred feasible candidate, if any.
func (r *Result) Best() (Candidate, bool) {
	if len(r.Candidates) == 0 {
		return Candidate{}, false
	}
	return r.Candidates[0], true
}

const policyParty = "policy"

func recipientParty(id string) string { return "recipient:" + id }

// Negotiate computes the message parameters usable for a group encryption.
//
// The policy is applied first (missing preferences are resolved against the
// baseline and forbidden items are removed), then whole candidate
// combinations are intersected against every recipient. The result does not
// depend on the order of recipients or on duplicated recipients.
func Negotiate(sender SenderCapabilities, recipients []RecipientProfile, policy Policy, baseline ProtocolBaseline) Result {
	forbiddenCiphers := cipherSet(policy.ForbiddenCiphers)
	forbiddenModes := modeSet(policy.ForbiddenAEADModes)
	forbiddenCompression := compressionSet(policy.ForbiddenCompression)
	allowedVersions := versionSet(policy.AllowedMessageVersions)
	allowedKeyVersions := keyVersionSet(policy.AllowedKeyVersions)

	senderKeyVersions := keyVersionSet(sender.KeyVersions)
	if len(allowedKeyVersions) > 0 {
		senderKeyVersions = intersectKeyVersions(senderKeyVersions, allowedKeyVersions)
	}

	normalized := make([]recipientView, 0, len(recipients))
	for _, r := range recipients {
		normalized = append(normalized, normalizeRecipient(r, policy, baseline))
	}

	// The universe of candidates is the sender's capability space, enumerated
	// in the sender's priority order so that feasible candidates come out
	// ranked without a separate sorting step.
	universe := senderUniverse(sender)

	var result Result
	for _, candidate := range universe {
		reasons := make([]ExclusionReason, 0, 2)

		if len(allowedVersions) > 0 && !allowedVersions[candidate.Version] {
			reasons = append(reasons, ExclusionReason{policyParty, "message version not allowed by policy"})
		}
		if policy.RequireAEAD && candidate.Version != MessageVersionSEIPDv2 {
			reasons = append(reasons, ExclusionReason{policyParty, "policy requires AEAD (SEIPDv2)"})
		}
		if forbiddenCiphers[candidate.Cipher] {
			reasons = append(reasons, ExclusionReason{policyParty, fmt.Sprintf("cipher %d forbidden by policy", byte(candidate.Cipher))})
		}
		if candidate.Version == MessageVersionSEIPDv2 && forbiddenModes[candidate.Mode] {
			reasons = append(reasons, ExclusionReason{policyParty, fmt.Sprintf("AEAD mode %d forbidden by policy", byte(candidate.Mode))})
		}
		if forbiddenCompression[candidate.Compression] {
			reasons = append(reasons, ExclusionReason{policyParty, fmt.Sprintf("compression %d forbidden by policy", byte(candidate.Compression))})
		}

		for _, r := range normalized {
			party := recipientParty(r.id)
			if !r.anyKeyVersion(senderKeyVersions) {
				reasons = append(reasons, ExclusionReason{party, "no common key version"})
			}
			if !r.messageVersions[candidate.Version] {
				reasons = append(reasons, ExclusionReason{party, "message version not supported"})
			}
			if candidate.Version == MessageVersionSEIPDv2 {
				if !r.aead[packet.CipherSuite{Cipher: candidate.Cipher, Mode: candidate.Mode}] {
					reasons = append(reasons, ExclusionReason{party, "AEAD cipher/mode pair not supported"})
				}
			} else if !r.symmetric[candidate.Cipher] {
				reasons = append(reasons, ExclusionReason{party, "symmetric algorithm not supported"})
			}
			if !r.compression[candidate.Compression] {
				reasons = append(reasons, ExclusionReason{party, "compression algorithm not supported"})
			}
		}

		if len(reasons) == 0 {
			result.Candidates = append(result.Candidates, candidate)
			continue
		}
		result.Excluded = append(result.Excluded, Exclusion{
			Candidate: candidate,
			Reasons:   stableReasons(reasons),
		})
	}
	return result
}

// recipientView is a recipient profile normalized into lookup sets. Set
// membership makes the outcome independent of preference list ordering.
type recipientView struct {
	id              string
	keyVersions     map[int]bool
	messageVersions map[MessageVersion]bool
	symmetric       map[packet.CipherFunction]bool
	compression     map[packet.CompressionAlgo]bool
	aead            map[packet.CipherSuite]bool
}

func (r recipientView) anyKeyVersion(senderVersions map[int]bool) bool {
	for v := range r.keyVersions {
		if senderVersions[v] {
			return true
		}
	}
	return false
}

func normalizeRecipient(r RecipientProfile, policy Policy, baseline ProtocolBaseline) recipientView {
	return recipientView{
		id:              r.ID,
		keyVersions:     keyVersionSet(resolveMissingInt(r.KeyVersions, baseline.KeyVersions, policy.ApplyImplicitPreferences)),
		messageVersions: versionSet(resolveMissingVersions(r.MessageVersions, baseline.MessageVersions, policy.ApplyImplicitPreferences)),
		symmetric:       cipherSet(resolveMissingCiphers(r.Symmetric, baseline.Symmetric, policy.ApplyImplicitPreferences)),
		compression:     compressionSet(resolveMissingCompression(r.Compression, baseline.Compression, policy.ApplyImplicitPreferences)),
		aead:            suiteSet(resolveMissingSuites(r.AEAD, baseline.AEAD, policy.ApplyImplicitPreferences)),
	}
}

// senderUniverse enumerates the sender's capability space in priority order.
// Unknown or unsupported algorithm IDs are dropped rather than causing a
// panic. AEAD cipher/mode pairs are kept intact so that no invalid
// combination is ever produced.
func senderUniverse(sender SenderCapabilities) []Candidate {
	var universe []Candidate
	seen := make(map[Candidate]bool)
	add := func(c Candidate) {
		if !seen[c] {
			seen[c] = true
			universe = append(universe, c)
		}
	}
	compressions := normalizeCompression(sender.Compression)
	for _, version := range normalizeMessageVersions(sender.MessageVersions) {
		switch version {
		case MessageVersionSEIPDv2:
			for _, suite := range normalizeSuites(sender.AEAD) {
				for _, compression := range compressions {
					add(Candidate{Version: version, Cipher: suite.Cipher, Mode: suite.Mode, Compression: compression})
				}
			}
		case MessageVersionSEIPDv1:
			for _, cipher := range normalizeCiphers(sender.Symmetric) {
				for _, compression := range compressions {
					add(Candidate{Version: version, Cipher: cipher, Compression: compression})
				}
			}
		}
	}
	return universe
}

// stableReasons deduplicates and sorts reasons so that diagnostics are
// stable regardless of recipient order or duplicated recipients.
func stableReasons(reasons []ExclusionReason) []ExclusionReason {
	seen := make(map[ExclusionReason]bool, len(reasons))
	out := reasons[:0]
	for _, r := range reasons {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Party != out[j].Party {
			return out[i].Party < out[j].Party
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

func isKnownKeyVersion(v int) bool { return v == 4 || v == 5 || v == 6 }

func isKnownCompression(c packet.CompressionAlgo) bool {
	return c == packet.CompressionNone || c == packet.CompressionZIP || c == packet.CompressionZLIB
}

func keyVersionSet(in []int) map[int]bool {
	out := make(map[int]bool, len(in))
	for _, v := range in {
		if isKnownKeyVersion(v) {
			out[v] = true
		}
	}
	return out
}

func intersectKeyVersions(a, b map[int]bool) map[int]bool {
	out := make(map[int]bool)
	for v := range a {
		if b[v] {
			out[v] = true
		}
	}
	return out
}

func normalizeMessageVersions(in []MessageVersion) []MessageVersion {
	seen := make(map[MessageVersion]bool, len(in))
	out := make([]MessageVersion, 0, len(in))
	for _, v := range in {
		if (v == MessageVersionSEIPDv1 || v == MessageVersionSEIPDv2) && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func versionSet(in []MessageVersion) map[MessageVersion]bool {
	out := make(map[MessageVersion]bool, len(in))
	for _, v := range normalizeMessageVersions(in) {
		out[v] = true
	}
	return out
}

func normalizeCiphers(in []packet.CipherFunction) []packet.CipherFunction {
	seen := make(map[packet.CipherFunction]bool, len(in))
	out := make([]packet.CipherFunction, 0, len(in))
	for _, c := range in {
		if c.IsSupported() && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func cipherSet(in []packet.CipherFunction) map[packet.CipherFunction]bool {
	out := make(map[packet.CipherFunction]bool, len(in))
	for _, c := range normalizeCiphers(in) {
		out[c] = true
	}
	return out
}

func normalizeCompression(in []packet.CompressionAlgo) []packet.CompressionAlgo {
	seen := make(map[packet.CompressionAlgo]bool, len(in))
	out := make([]packet.CompressionAlgo, 0, len(in))
	for _, c := range in {
		if isKnownCompression(c) && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func compressionSet(in []packet.CompressionAlgo) map[packet.CompressionAlgo]bool {
	out := make(map[packet.CompressionAlgo]bool, len(in))
	for _, c := range normalizeCompression(in) {
		out[c] = true
	}
	return out
}

func normalizeSuites(in []packet.CipherSuite) []packet.CipherSuite {
	seen := make(map[packet.CipherSuite]bool, len(in))
	out := make([]packet.CipherSuite, 0, len(in))
	for _, s := range in {
		if s.Cipher.IsSupported() && s.Mode.IsSupported() && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func suiteSet(in []packet.CipherSuite) map[packet.CipherSuite]bool {
	out := make(map[packet.CipherSuite]bool, len(in))
	for _, s := range normalizeSuites(in) {
		out[s] = true
	}
	return out
}

func modeSet(in []packet.AEADMode) map[packet.AEADMode]bool {
	out := make(map[packet.AEADMode]bool, len(in))
	for _, m := range in {
		if m.IsSupported() {
			out[m] = true
		}
	}
	return out
}

func resolveMissingInt(in, implicit []int, apply bool) []int {
	if in == nil && apply {
		return implicit
	}
	return in
}

func resolveMissingVersions(in, implicit []MessageVersion, apply bool) []MessageVersion {
	if in == nil && apply {
		return implicit
	}
	return in
}

func resolveMissingCiphers(in, implicit []packet.CipherFunction, apply bool) []packet.CipherFunction {
	if in == nil && apply {
		return implicit
	}
	return in
}

func resolveMissingCompression(in, implicit []packet.CompressionAlgo, apply bool) []packet.CompressionAlgo {
	if in == nil && apply {
		return implicit
	}
	return in
}

func resolveMissingSuites(in, implicit []packet.CipherSuite, apply bool) []packet.CipherSuite {
	if in == nil && apply {
		return implicit
	}
	return in
}
