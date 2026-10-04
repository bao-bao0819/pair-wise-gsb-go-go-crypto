// Package negotiate implements pure, deterministic selection of OpenPGP
// message parameters for encrypting one message to multiple recipients.
//
// The negotiator is a pure function: it performs no I/O, never consults
// keyservers, and never decides whether recipient preferences are
// authentic. The caller is responsible for verifying the recipients' keys
// and preference signatures before building the Recipient descriptors.
//
// Negotiation proceeds in two phases. First, the Policy is applied: empty
// preference lists are filled from the protocol Baseline and forbidden
// algorithms are removed. Second, the resulting feasible combinations are
// intersected across all recipients as whole candidates, so a cipher and
// an AEAD mode are never selected independently only to discover that
// their combination is unsupported. Candidates are ranked exclusively by
// the sender's explicit preference order; the order or duplication of
// recipients in the input never changes the outcome.
package negotiate

import (
	"fmt"
	"sort"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// MessageVersion identifies the wire-format family of the encrypted
// message a party can produce or parse.
type MessageVersion uint8

const (
	// MessageVersionSEIPDv1 is the v1 Symmetrically Encrypted Integrity
	// Protected Data packet (CFB mode with MDC), used with v4 keys.
	MessageVersionSEIPDv1 MessageVersion = 1
	// MessageVersionSEIPDv2 is the v2 SEIPD packet (AEAD), used with v6
	// keys and requiring AEAD cipher suites.
	MessageVersionSEIPDv2 MessageVersion = 2
)

// Recipient describes the message capabilities of a single recipient, as
// already verified by the caller. Empty preference lists mean "no
// information published" and are filled from Policy.Fallback; unknown
// algorithm identifiers are treated as unsupported and ignored.
type Recipient struct {
	// Name identifies the recipient in diagnostics.
	Name string
	// Versions are the message versions the recipient can parse.
	Versions []MessageVersion
	// Ciphers are the symmetric ciphers the recipient accepts.
	Ciphers []packet.CipherFunction
	// Compressions are the compression algorithms the recipient accepts.
	Compressions []packet.CompressionAlgo
	// AEAD lists the AEAD cipher suites (cipher/mode pairs) the recipient
	// accepts. Pairs are matched as a whole: advertising (AES-128, OCB)
	// and (AES-256, GCM) does not imply support for (AES-256, OCB).
	AEAD []packet.CipherSuite
}

// Sender describes the sending implementation's capabilities. Every list
// is ranked in decreasing order of preference; this explicit order is the
// only source of candidate ranking.
type Sender struct {
	Versions     []MessageVersion
	Ciphers      []packet.CipherFunction
	Compressions []packet.CompressionAlgo
	AEAD         []packet.CipherSuite
}

// Baseline expresses the capabilities the protocol mandates. It is kept
// separate from Policy so that protocol requirements and application
// policy remain independently auditable.
type Baseline struct {
	Versions     []MessageVersion
	Ciphers      []packet.CipherFunction
	Compressions []packet.CompressionAlgo
	AEAD         []packet.CipherSuite
}

// DefaultBaseline returns the capabilities required by the protocol:
// SEIPDv1 messages, TripleDES, no compression, and the mandatory-to-implement
// AES-128/OCB AEAD suite.
func DefaultBaseline() Baseline {
	return Baseline{
		Versions:     []MessageVersion{MessageVersionSEIPDv1},
		Ciphers:      []packet.CipherFunction{packet.Cipher3DES},
		Compressions: []packet.CompressionAlgo{packet.CompressionNone},
		AEAD: []packet.CipherSuite{
			{Cipher: packet.CipherAES128, Mode: packet.AEADModeOCB},
		},
	}
}

// Policy expresses application-level restrictions. A forbidden algorithm
// is never selected, even if it is the only common choice; the negotiator
// never silently downgrades to a forbidden algorithm.
type Policy struct {
	// Fallback describes what a recipient is assumed to support when one
	// of its preference lists is empty. DefaultBaseline() is the usual
	// choice; applications may tighten it.
	Fallback Baseline
	// RequireAEAD rejects all SEIPDv1 (MDC) candidates.
	RequireAEAD bool
	// ForbiddenVersions, ForbiddenCiphers, ForbiddenCompressions and
	// ForbiddenAEADModes ban individual algorithms.
	ForbiddenVersions     map[MessageVersion]bool
	ForbiddenCiphers      map[packet.CipherFunction]bool
	ForbiddenCompressions map[packet.CompressionAlgo]bool
	ForbiddenAEADModes    map[packet.AEADMode]bool
}

// Candidate is one complete, self-consistent set of message parameters.
type Candidate struct {
	Version     MessageVersion
	Cipher      packet.CipherFunction
	Compression packet.CompressionAlgo
	// AEADMode is the AEAD mode for SEIPDv2 candidates, and zero for
	// SEIPDv1 candidates, which use CFB+MDC instead.
	AEADMode packet.AEADMode
}

// Reason explains why a candidate was excluded. Source is the name of the
// recipient that excluded the candidate, or "policy".
type Reason struct {
	Source string
	Detail string
}

// Rejection pairs an infeasible candidate with the reasons for its
// exclusion. Reasons are ordered deterministically: policy reasons first,
// then recipient reasons sorted by recipient name.
type Rejection struct {
	Candidate Candidate
	Reasons   []Reason
}

// Result is the outcome of a negotiation.
type Result struct {
	// Selected is the highest-ranked feasible candidate, or nil if the
	// intersection is empty.
	Selected *Candidate
	// Feasible lists all feasible candidates in rank order.
	Feasible []Candidate
	// Rejected lists every infeasible candidate with stable diagnostics.
	Rejected []Rejection
}

const sourcePolicy = "policy"

// Negotiate selects message parameters acceptable to the sender, every
// recipient, and the policy. It never fails: an empty intersection is
// reported through Result.Rejected.
func Negotiate(recipients []Recipient, sender Sender, policy Policy) Result {
	normalized := normalizeRecipients(recipients, policy)
	candidates := generateCandidates(sender)

	var result Result
	for _, candidate := range candidates {
		reasons := policyReasons(candidate, policy)
		if len(reasons) == 0 {
			for i := range normalized {
				reasons = append(reasons, recipientReasons(candidate, &normalized[i])...)
			}
		}
		if len(reasons) == 0 {
			if result.Selected == nil {
				selected := candidate
				result.Selected = &selected
			}
			result.Feasible = append(result.Feasible, candidate)
		} else {
			result.Rejected = append(result.Rejected, Rejection{Candidate: candidate, Reasons: reasons})
		}
	}
	return result
}

// recipientSets holds a recipient's effective capabilities after missing
// preferences have been filled and unknown or forbidden algorithms removed.
type recipientSets struct {
	name         string
	versions     map[MessageVersion]bool
	ciphers      map[packet.CipherFunction]bool
	compressions map[packet.CompressionAlgo]bool
	aead         map[packet.CipherSuite]bool
}

func normalizeRecipients(recipients []Recipient, policy Policy) []recipientSets {
	normalized := make([]recipientSets, 0, len(recipients))
	for _, recipient := range recipients {
		versions := recipient.Versions
		if len(versions) == 0 {
			versions = policy.Fallback.Versions
		}
		ciphers := recipient.Ciphers
		if len(ciphers) == 0 {
			ciphers = policy.Fallback.Ciphers
		}
		compressions := recipient.Compressions
		if len(compressions) == 0 {
			compressions = policy.Fallback.Compressions
		}
		aead := recipient.AEAD
		if len(aead) == 0 {
			aead = policy.Fallback.AEAD
		}
		sets := recipientSets{
			name:         recipient.Name,
			versions:     versionSet(versions, policy),
			ciphers:      cipherSet(ciphers, policy),
			compressions: compressionSet(compressions, policy),
			aead:         aeadSet(aead, policy),
		}
		normalized = append(normalized, sets)
	}
	// Sort by name so that recipient input order cannot change the
	// outcome, and drop exact duplicates so repeated recipients do not
	// either.
	sort.SliceStable(normalized, func(i, j int) bool {
		return normalized[i].name < normalized[j].name
	})
	unique := normalized[:0]
	for i, sets := range normalized {
		if i > 0 && sets.fingerprint() == normalized[i-1].fingerprint() {
			continue
		}
		unique = append(unique, sets)
	}
	return unique
}

// fingerprint returns a canonical string form of the recipient's effective
// capabilities, used to detect exact duplicates.
func (sets *recipientSets) fingerprint() string {
	fingerprint := sets.name
	var versions []int
	for version := range sets.versions {
		versions = append(versions, int(version))
	}
	sort.Ints(versions)
	for _, version := range versions {
		fingerprint += fmt.Sprintf("|v%d", version)
	}
	var ciphers []int
	for cipher := range sets.ciphers {
		ciphers = append(ciphers, int(cipher))
	}
	sort.Ints(ciphers)
	for _, cipher := range ciphers {
		fingerprint += fmt.Sprintf("|c%d", cipher)
	}
	var compressions []int
	for compression := range sets.compressions {
		compressions = append(compressions, int(compression))
	}
	sort.Ints(compressions)
	for _, compression := range compressions {
		fingerprint += fmt.Sprintf("|z%d", compression)
	}
	var suites []string
	for suite := range sets.aead {
		suites = append(suites, fmt.Sprintf("%d:%d", suite.Cipher, suite.Mode))
	}
	sort.Strings(suites)
	for _, suite := range suites {
		fingerprint += "|a" + suite
	}
	return fingerprint
}

func versionSet(versions []MessageVersion, policy Policy) map[MessageVersion]bool {
	set := make(map[MessageVersion]bool, len(versions))
	for _, version := range versions {
		if version != MessageVersionSEIPDv1 && version != MessageVersionSEIPDv2 {
			continue
		}
		if policy.ForbiddenVersions[version] {
			continue
		}
		set[version] = true
	}
	return set
}

func cipherSet(ciphers []packet.CipherFunction, policy Policy) map[packet.CipherFunction]bool {
	set := make(map[packet.CipherFunction]bool, len(ciphers))
	for _, cipher := range ciphers {
		if !cipher.IsSupported() {
			continue
		}
		if policy.ForbiddenCiphers[cipher] {
			continue
		}
		set[cipher] = true
	}
	return set
}

func compressionSet(compressions []packet.CompressionAlgo, policy Policy) map[packet.CompressionAlgo]bool {
	set := make(map[packet.CompressionAlgo]bool, len(compressions))
	for _, compression := range compressions {
		if !isSupportedCompression(compression) {
			continue
		}
		if policy.ForbiddenCompressions[compression] {
			continue
		}
		set[compression] = true
	}
	return set
}

func aeadSet(suites []packet.CipherSuite, policy Policy) map[packet.CipherSuite]bool {
	set := make(map[packet.CipherSuite]bool, len(suites))
	for _, suite := range suites {
		if !suite.Cipher.IsSupported() || !suite.Mode.IsSupported() {
			continue
		}
		if policy.ForbiddenCiphers[suite.Cipher] || policy.ForbiddenAEADModes[suite.Mode] {
			continue
		}
		set[suite] = true
	}
	return set
}

// generateCandidates enumerates whole candidates from the sender's ranked
// lists. Rank order is: message version first, then cipher (or AEAD
// suite), then compression, each following the sender's explicit order.
// Unknown algorithm identifiers are dropped rather than causing a panic.
func generateCandidates(sender Sender) []Candidate {
	var candidates []Candidate
	for _, version := range dedupeVersions(sender.Versions) {
		switch version {
		case MessageVersionSEIPDv1:
			for _, cipher := range dedupeCiphers(sender.Ciphers) {
				for _, compression := range dedupeCompressions(sender.Compressions) {
					candidates = append(candidates, Candidate{
						Version:     version,
						Cipher:      cipher,
						Compression: compression,
					})
				}
			}
		case MessageVersionSEIPDv2:
			for _, suite := range dedupeSuites(sender.AEAD) {
				for _, compression := range dedupeCompressions(sender.Compressions) {
					candidates = append(candidates, Candidate{
						Version:     version,
						Cipher:      suite.Cipher,
						Compression: compression,
						AEADMode:    suite.Mode,
					})
				}
			}
		}
	}
	return candidates
}

func dedupeVersions(versions []MessageVersion) []MessageVersion {
	seen := make(map[MessageVersion]bool, len(versions))
	var out []MessageVersion
	for _, version := range versions {
		if version != MessageVersionSEIPDv1 && version != MessageVersionSEIPDv2 {
			continue
		}
		if !seen[version] {
			seen[version] = true
			out = append(out, version)
		}
	}
	return out
}

func dedupeCiphers(ciphers []packet.CipherFunction) []packet.CipherFunction {
	seen := make(map[packet.CipherFunction]bool, len(ciphers))
	var out []packet.CipherFunction
	for _, cipher := range ciphers {
		if !cipher.IsSupported() {
			continue
		}
		if !seen[cipher] {
			seen[cipher] = true
			out = append(out, cipher)
		}
	}
	return out
}

func dedupeCompressions(compressions []packet.CompressionAlgo) []packet.CompressionAlgo {
	seen := make(map[packet.CompressionAlgo]bool, len(compressions))
	var out []packet.CompressionAlgo
	for _, compression := range compressions {
		if !isSupportedCompression(compression) {
			continue
		}
		if !seen[compression] {
			seen[compression] = true
			out = append(out, compression)
		}
	}
	return out
}

func dedupeSuites(suites []packet.CipherSuite) []packet.CipherSuite {
	seen := make(map[packet.CipherSuite]bool, len(suites))
	var out []packet.CipherSuite
	for _, suite := range suites {
		if !suite.Cipher.IsSupported() || !suite.Mode.IsSupported() {
			continue
		}
		if !seen[suite] {
			seen[suite] = true
			out = append(out, suite)
		}
	}
	return out
}

func isSupportedCompression(compression packet.CompressionAlgo) bool {
	switch compression {
	case packet.CompressionNone, packet.CompressionZIP, packet.CompressionZLIB:
		return true
	}
	return false
}

// policyReasons reports the policy-level exclusions for a candidate. A
// candidate excluded here is rejected before the recipient intersection,
// mirroring the "policy first, then intersect" order.
func policyReasons(candidate Candidate, policy Policy) []Reason {
	var reasons []Reason
	if policy.RequireAEAD && candidate.Version != MessageVersionSEIPDv2 {
		reasons = append(reasons, Reason{Source: sourcePolicy, Detail: "AEAD (SEIPDv2) message required"})
	}
	if policy.ForbiddenVersions[candidate.Version] {
		reasons = append(reasons, Reason{Source: sourcePolicy, Detail: fmt.Sprintf("message version %d forbidden", candidate.Version)})
	}
	if policy.ForbiddenCiphers[candidate.Cipher] {
		reasons = append(reasons, Reason{Source: sourcePolicy, Detail: fmt.Sprintf("cipher %d forbidden", candidate.Cipher)})
	}
	if candidate.AEADMode != 0 && policy.ForbiddenAEADModes[candidate.AEADMode] {
		reasons = append(reasons, Reason{Source: sourcePolicy, Detail: fmt.Sprintf("aead mode %d forbidden", candidate.AEADMode)})
	}
	if policy.ForbiddenCompressions[candidate.Compression] {
		reasons = append(reasons, Reason{Source: sourcePolicy, Detail: fmt.Sprintf("compression %d forbidden", candidate.Compression)})
	}
	return reasons
}

func recipientReasons(candidate Candidate, recipient *recipientSets) []Reason {
	var reasons []Reason
	if !recipient.versions[candidate.Version] {
		reasons = append(reasons, Reason{Source: recipient.name, Detail: fmt.Sprintf("message version %d not supported", candidate.Version)})
	}
	if candidate.Version == MessageVersionSEIPDv2 {
		suite := packet.CipherSuite{Cipher: candidate.Cipher, Mode: candidate.AEADMode}
		if !recipient.aead[suite] {
			reasons = append(reasons, Reason{Source: recipient.name, Detail: fmt.Sprintf("aead suite (cipher %d, mode %d) not supported", candidate.Cipher, candidate.AEADMode)})
		}
	} else if !recipient.ciphers[candidate.Cipher] {
		reasons = append(reasons, Reason{Source: recipient.name, Detail: fmt.Sprintf("cipher %d not supported", candidate.Cipher)})
	}
	if !recipient.compressions[candidate.Compression] {
		reasons = append(reasons, Reason{Source: recipient.name, Detail: fmt.Sprintf("compression %d not supported", candidate.Compression)})
	}
	return reasons
}
