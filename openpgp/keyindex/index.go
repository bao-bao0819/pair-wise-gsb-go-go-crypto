package keyindex

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Lookup status values reported by key-ID searches. These make the three
// possible outcomes explicit instead of silently returning the first key
// encountered.
const (
	// LookupUnique means exactly one indexed key matches the query.
	LookupUnique = iota
	// LookupMissing means no indexed key matches the query.
	LookupMissing
	// LookupAmbiguous means more than one distinct key matches the query.
	// Short key IDs are only 32 bits, so collisions must be expected once a
	// verification tool has accumulated many key packages.
	LookupAmbiguous
)

// Entry is one indexed public key packet together with the sources from which
// it was imported. A primary key and each of its subkeys are indexed as
// separate entries. An Entry carries no trust information: membership in the
// index says nothing about whether the key is valid or trustworthy.
type Entry struct {
	// Identity is the canonical, recomputed identity of the key.
	Identity Identity
	// PublicKey is the indexed public key packet.
	PublicKey *packet.PublicKey
	// IsSubkey reports whether the packet is a subkey rather than a primary
	// key.
	IsSubkey bool
	// Sources are the origins supplied when the key was imported (for example
	// file paths or keyring names). Importing the same key again merges the
	// new sources into this list instead of creating a duplicate entry. The
	// slice is sorted and deduplicated.
	Sources []string
}

// Result is the explicit outcome of a key-ID lookup.
type Result struct {
	// Status is LookupUnique, LookupMissing or LookupAmbiguous.
	Status int
	// Candidates contains the matching entries. It has exactly one element
	// when Status is LookupUnique, is empty when Status is LookupMissing, and
	// holds every distinct matching key when Status is LookupAmbiguous.
	//
	// The slice is owned by the immutable snapshot that produced it: later
	// imports can never change its length, order or contents, and callers
	// must not modify it.
	Candidates []*Entry
}

// Unique returns the single matching entry. It returns an error when the
// lookup is missing or ambiguous, so callers can never accidentally use the
// first of several colliding keys.
func (r Result) Unique() (*Entry, error) {
	switch r.Status {
	case LookupUnique:
		return r.Candidates[0], nil
	case LookupMissing:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("%w: %d distinct keys share key id %s",
			ErrAmbiguous, len(r.Candidates), shortIDString(r.Candidates))
	}
}

var (
	// ErrNotFound is returned by exact lookups when no key matches.
	ErrNotFound = errors.New("keyindex: no key matches the given identifier")
	// ErrAmbiguous is returned when a short key ID matches more than one
	// distinct key. The caller must disambiguate with a full fingerprint.
	ErrAmbiguous = errors.New("keyindex: ambiguous key id, multiple distinct keys match")
)

// fingerprintKey addresses a key uniquely by packet version and complete
// fingerprint. Two keys colliding on a short ID always have distinct
// fingerprintKeys.
type fingerprintKey struct {
	version     int
	fingerprint string
}

// snapshot is an immutable point-in-time view of the index. Snapshots are safe
// for concurrent use. All maps and slices in a snapshot are treated as
// read-only; imports build a new snapshot instead of mutating an existing one,
// so a candidate slice handed out by one snapshot can never change underneath a
// goroutine that is still iterating it.
type snapshot struct {
	// entries holds every distinct indexed key, keyed by full identity.
	entries map[fingerprintKey]*Entry
	// byShortID holds all keys sharing a 32-bit short key ID. Every value
	// slice is sorted by (version, fingerprint) and is never mutated in
	// place.
	byShortID map[uint32][]*Entry
}

// Index is a growing, concurrency-safe collection of public keys. Reads happen
// against immutable snapshots; Add swaps in a new snapshot atomically.
// The zero value is ready to use.
type Index struct {
	mu sync.RWMutex
	s  *snapshot
}

// New returns an empty index.
func New() *Index {
	return &Index{s: newSnapshot()}
}

func newSnapshot() *snapshot {
	return &snapshot{
		entries:   make(map[fingerprintKey]*Entry),
		byShortID: make(map[uint32][]*Entry),
	}
}

// Snapshot returns a read-only, immutable view of the index. The returned
// snapshot is unaffected by subsequent calls to Add: candidate slices obtained
// from it remain stable while callers use them, and snapshots may be queried
// concurrently without further locking.
func (ix *Index) Snapshot() *Snapshot {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	if ix.s == nil {
		// Do not mutate the index under the read lock: return a standalone
		// empty view. It behaves identically to a snapshot of an empty index.
		return &Snapshot{s: newSnapshot()}
	}
	return &Snapshot{s: ix.s}
}

// Snapshot is a read-only view captured at one point in time.
type Snapshot struct {
	s *snapshot
}

// FindByFingerprint returns the unique key with the given packet version and
// complete fingerprint. The fingerprint length must match the version (20
// bytes for v4, 32 bytes for v6); otherwise ErrInvalidFingerprint is returned.
// It returns ErrNotFound when no such key is indexed. A full fingerprint
// cannot be ambiguous.
func (snap *Snapshot) FindByFingerprint(version int, fingerprint []byte) (*Entry, error) {
	if err := ValidateFingerprint(version, fingerprint); err != nil {
		return nil, err
	}
	key := fingerprintKey{version: version, fingerprint: string(fingerprint)}
	if entry, ok := snap.s.entries[key]; ok {
		return entry, nil
	}
	return nil, fmt.Errorf("%w: version %d fingerprint %X", ErrNotFound, version, fingerprint)
}

// LookupShortKeyID returns every key whose conventional 32-bit short key ID
// matches id, with an explicit unique/missing/ambiguous status. Both v4 and v6
// keys participate: for v6 the short ID is the low 32 bits of the v6 key ID.
func (snap *Snapshot) LookupShortKeyID(id uint32) Result {
	candidates := snap.s.byShortID[id]
	switch len(candidates) {
	case 0:
		return Result{Status: LookupMissing}
	case 1:
		return Result{Status: LookupUnique, Candidates: candidates}
	default:
		return Result{Status: LookupAmbiguous, Candidates: candidates}
	}
}

// LookupFullKeyID returns every key whose full 64-bit key ID matches id. The
// result is still reported with an explicit status: collisions on full key IDs
// are astronomically unlikely but not asserted away, and (unlike a fingerprint
// lookup) the key version is not part of the query.
func (snap *Snapshot) LookupFullKeyID(id uint64) Result {
	var matched []*Entry
	for _, entry := range snap.s.entries {
		if entry.Identity.KeyID == id {
			matched = append(matched, entry)
		}
	}
	sortEntries(matched)
	switch len(matched) {
	case 0:
		return Result{Status: LookupMissing}
	case 1:
		return Result{Status: LookupUnique, Candidates: matched}
	default:
		return Result{Status: LookupAmbiguous, Candidates: matched}
	}
}

// AddKey indexes a single public key packet. The identity is recomputed from
// the packet's canonical representation rather than read from its cached
// Fingerprint/KeyId fields. source describes where the key package came from;
// importing the same key again merges sources instead of duplicating it.
func (ix *Index) AddKey(pk *packet.PublicKey, isSubkey bool, source string) error {
	identity, err := ComputeIdentity(pk)
	if err != nil {
		return err
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.s == nil {
		ix.s = newSnapshot()
	}
	ix.s = ix.s.withKey(pk, isSubkey, source, identity)
	return nil
}

// AddEntity indexes the primary key and every subkey of an entity. source is
// recorded on each resulting entry and merged on repeat imports.
func (ix *Index) AddEntity(entity *openpgp.Entity, source string) error {
	if entity == nil || entity.PrimaryKey == nil {
		return ErrNilPublicKey
	}

	// Validate every packet's canonical identity before mutating the index so
	// a bad subkey cannot leave a partially imported entity behind.
	type pending struct {
		pk       *packet.PublicKey
		isSubkey bool
		identity Identity
	}
	keys := make([]pending, 0, 1+len(entity.Subkeys))

	primaryIdentity, err := ComputeIdentity(entity.PrimaryKey)
	if err != nil {
		return err
	}
	keys = append(keys, pending{entity.PrimaryKey, false, primaryIdentity})

	for _, subkey := range entity.Subkeys {
		if subkey.PublicKey == nil {
			continue
		}
		subIdentity, err := ComputeIdentity(subkey.PublicKey)
		if err != nil {
			return err
		}
		keys = append(keys, pending{subkey.PublicKey, true, subIdentity})
	}

	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.s == nil {
		ix.s = newSnapshot()
	}
	for _, k := range keys {
		ix.s = ix.s.withKey(k.pk, k.isSubkey, source, k.identity)
	}
	return nil
}

// withKey returns a new snapshot containing the given key. The receiver
// snapshot is never mutated, preserving all earlier Snapshot views.
func (s *snapshot) withKey(pk *packet.PublicKey, isSubkey bool, source string, identity Identity) *snapshot {
	key := fingerprintKey{
		version:     identity.Version,
		fingerprint: string(identity.Fingerprint),
	}

	next := &snapshot{
		entries:   make(map[fingerprintKey]*Entry, len(s.entries)+1),
		byShortID: make(map[uint32][]*Entry, len(s.byShortID)),
	}
	for k, entry := range s.entries {
		next.entries[k] = entry
	}
	for shortID, entries := range s.byShortID {
		next.byShortID[shortID] = entries
	}

	if existing, ok := next.entries[key]; ok {
		// Same canonical key imported again: merge origins only and rebuild
		// the affected short-ID slice so existing snapshots keep their slice.
		merged := *existing
		merged.Sources = mergeSources(existing.Sources, source)
		next.entries[key] = &merged
		next.rebuildShortID(identity.ShortKeyID)
		return next
	}

	entry := &Entry{
		Identity:  identity,
		PublicKey: pk,
		IsSubkey:  isSubkey,
		Sources:   mergeSources(nil, source),
	}
	next.entries[key] = entry
	next.rebuildShortID(identity.ShortKeyID)
	return next
}

// rebuildShortID reconstructs one byShortID bucket from the entry set,
// producing a fresh sorted slice that does not alias any earlier snapshot.
func (s *snapshot) rebuildShortID(shortID uint32) {
	var bucket []*Entry
	for _, entry := range s.entries {
		if entry.Identity.ShortKeyID == shortID {
			bucket = append(bucket, entry)
		}
	}
	sortEntries(bucket)
	if len(bucket) == 0 {
		delete(s.byShortID, shortID)
		return
	}
	s.byShortID[shortID] = bucket
}

func sortEntries(entries []*Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Identity.Version != entries[j].Identity.Version {
			return entries[i].Identity.Version < entries[j].Identity.Version
		}
		return bytes.Compare(entries[i].Identity.Fingerprint, entries[j].Identity.Fingerprint) < 0
	})
}

// mergeSources returns a new sorted, deduplicated source list containing
// existing and source.
func mergeSources(existing []string, source string) []string {
	merged := make([]string, 0, len(existing)+1)
	merged = append(merged, existing...)
	if source != "" {
		merged = append(merged, source)
	}
	sort.Strings(merged)
	deduped := merged[:0]
	for _, src := range merged {
		if len(deduped) == 0 || deduped[len(deduped)-1] != src {
			deduped = append(deduped, src)
		}
	}
	return deduped
}

func shortIDString(candidates []*Entry) string {
	if len(candidates) == 0 {
		return ""
	}
	return fmt.Sprintf("%08X", candidates[0].Identity.ShortKeyID)
}
