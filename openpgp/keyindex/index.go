package keyindex

import (
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// A Record is a single indexed public key. Importing the same key (same
// version and fingerprint) more than once merges the provenance labels
// instead of creating a second record.
type Record struct {
	Identity KeyIdentity
	// Key is the key material as imported. It is shared with the caller
	// and must not be mutated.
	Key *packet.PublicKey
	// Subkey reports whether the key was imported as a subkey of an entity.
	Subkey bool

	sources []string
}

// Sources returns the provenance labels recorded for this key.
func (r *Record) Sources() []string {
	return append([]string(nil), r.sources...)
}

// Status is the explicit outcome of a lookup.
type Status int

const (
	// Missing means no record matched the query.
	Missing Status = iota
	// Unique means exactly one record matched the query.
	Unique
	// Ambiguous means more than one record matched the query. This can only
	// happen for key ID lookups, when distinct fingerprints share a key ID.
	Ambiguous
)

func (s Status) String() string {
	switch s {
	case Missing:
		return "missing"
	case Unique:
		return "unique"
	case Ambiguous:
		return "ambiguous"
	}
	return "unknown"
}

// A Result is the outcome of resolving a lookup against a Snapshot.
type Result struct {
	Status Status
	// Record is the matching record when Status is Unique, nil otherwise.
	Record *Record
	// Candidates holds all matching records when Status is Ambiguous.
	// The slice is owned by the caller and is never mutated by the index.
	Candidates []*Record
}

type fingerprintKey struct {
	version     int
	fingerprint string
}

// tables is the immutable state of the index. Once published, the maps and
// the slices they contain are never modified; imports build replacement
// tables and swap them in, so snapshots and in-flight lookups keep a stable
// view.
type tables struct {
	byFingerprint map[fingerprintKey]*Record
	byKeyID       map[uint64][]*Record
}

func newTables() *tables {
	return &tables{
		byFingerprint: make(map[fingerprintKey]*Record),
		byKeyID:       make(map[uint64][]*Record),
	}
}

// An Index accumulates public keys and hands out read-only Snapshots for
// querying. It is safe for concurrent use.
type Index struct {
	mu     sync.Mutex
	tables *tables
}

// NewIndex returns an empty Index.
func NewIndex() *Index {
	return &Index{tables: newTables()}
}

// Add imports a single public key under the given provenance label. The
// key's identity is computed from its canonical serialization (see
// IdentityOf); cached fingerprint or key ID fields that disagree with the
// key material are rejected. Importing a key that is already present merges
// the label into the existing record's sources.
func (ix *Index) Add(pk *packet.PublicKey, source string) (*Record, error) {
	identity, err := IdentityOf(pk)
	if err != nil {
		return nil, err
	}
	return ix.add(identity, pk, pk.IsSubkey, source), nil
}

// AddEntity imports an entity's primary key and all of its subkeys under
// the given provenance label.
func (ix *Index) AddEntity(e *openpgp.Entity, source string) error {
	if _, err := ix.Add(e.PrimaryKey, source); err != nil {
		return err
	}
	for i := range e.Subkeys {
		if _, err := ix.Add(e.Subkeys[i].PublicKey, source); err != nil {
			return err
		}
	}
	return nil
}

// addIdentity imports a key under a caller-supplied identity. It is the
// seam used by tests to exercise collision handling with controllable
// identifiers; production code should use Add, which derives the identity
// from the key material itself.
func (ix *Index) addIdentity(identity KeyIdentity, key *packet.PublicKey, subkey bool, source string) *Record {
	return ix.add(identity, key, subkey, source)
}

func (ix *Index) add(identity KeyIdentity, key *packet.PublicKey, subkey bool, source string) *Record {
	ix.mu.Lock()
	defer ix.mu.Unlock()

	fpk := fingerprintKey{version: identity.Version, fingerprint: string(identity.Fingerprint)}
	old := ix.tables
	if existing, ok := old.byFingerprint[fpk]; ok {
		// Duplicate import of the same key: merge the source label.
		for _, s := range existing.sources {
			if s == source {
				return existing
			}
		}
		merged := *existing
		merged.sources = append(append([]string(nil), existing.sources...), source)
		next := old.clone()
		next.byFingerprint[fpk] = &merged
		next.byKeyID[identity.KeyID] = replaceRecord(next.byKeyID[identity.KeyID], &merged)
		ix.tables = next
		return &merged
	}

	record := &Record{
		Identity: KeyIdentity{
			Version:     identity.Version,
			Fingerprint: append([]byte(nil), identity.Fingerprint...),
			KeyID:       identity.KeyID,
		},
		Key:     key,
		Subkey:  subkey,
		sources: []string{source},
	}
	next := old.clone()
	next.byFingerprint[fpk] = record
	// Append to a fresh slice so snapshots holding the old bucket are
	// unaffected by this import.
	bucket := old.byKeyID[identity.KeyID]
	grown := make([]*Record, len(bucket)+1)
	copy(grown, bucket)
	grown[len(bucket)] = record
	next.byKeyID[identity.KeyID] = grown
	ix.tables = next
	return record
}

func (t *tables) clone() *tables {
	next := &tables{
		byFingerprint: make(map[fingerprintKey]*Record, len(t.byFingerprint)+1),
		byKeyID:       make(map[uint64][]*Record, len(t.byKeyID)+1),
	}
	for k, v := range t.byFingerprint {
		next.byFingerprint[k] = v
	}
	for k, v := range t.byKeyID {
		next.byKeyID[k] = v
	}
	return next
}

func replaceRecord(bucket []*Record, record *Record) []*Record {
	next := make([]*Record, len(bucket))
	for i, r := range bucket {
		if r.Identity.Version == record.Identity.Version &&
			string(r.Identity.Fingerprint) == string(record.Identity.Fingerprint) {
			next[i] = record
		} else {
			next[i] = r
		}
	}
	return next
}

// Snapshot returns a read-only, consistent view of the index. The snapshot
// is unaffected by later imports and is safe for concurrent queries.
func (ix *Index) Snapshot() *Snapshot {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return &Snapshot{tables: ix.tables}
}

// A Snapshot is an immutable view of an Index. It is safe for concurrent
// use, and imports that happen after the snapshot was taken never change
// the results it returns or the slices behind them.
type Snapshot struct {
	tables *tables
}

// Len returns the number of distinct keys in the snapshot.
func (s *Snapshot) Len() int {
	return len(s.tables.byFingerprint)
}

// ByFingerprint looks up a key by version and full fingerprint. The version
// and fingerprint length must agree (20 bytes for v4, 32 bytes for v5/v6);
// otherwise an error wrapping ErrUnsupportedVersion or ErrFingerprintLength
// is returned.
func (s *Snapshot) ByFingerprint(version int, fingerprint []byte) (Result, error) {
	if _, err := fingerprintLength(version); err != nil {
		return Result{Status: Missing}, err
	}
	if _, err := keyIDFromFingerprint(version, fingerprint); err != nil {
		return Result{Status: Missing}, err
	}
	record, ok := s.tables.byFingerprint[fingerprintKey{version: version, fingerprint: string(fingerprint)}]
	if !ok {
		return Result{Status: Missing}, nil
	}
	return Result{Status: Unique, Record: record}, nil
}

// ByKeyID looks up keys by their 64-bit key ID. The result is explicitly
// Unique, Missing, or Ambiguous; callers must not assume the first match is
// the intended key when the status is Ambiguous.
func (s *Snapshot) ByKeyID(keyID uint64) Result {
	bucket := s.tables.byKeyID[keyID]
	switch len(bucket) {
	case 0:
		return Result{Status: Missing}
	case 1:
		return Result{Status: Unique, Record: bucket[0]}
	default:
		return Result{Status: Ambiguous, Candidates: append([]*Record(nil), bucket...)}
	}
}
