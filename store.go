// Shared in-memory store for the forge.
//
// One Store serves every surface (REST, git smart HTTP, GraphQL, MCP), so
// an object created through any of them is visible through all the others
// with stable ids. Every Store method locks internally; callers never touch
// Repo maps except while holding the store lock, and never mutate them
// except through Store methods. Reads of immutable identity fields (ID,
// Owner, Name) on a *Repo from a getter are safe without the lock.
//
// Determinism: nothing stored or emitted depends on the wall clock or on
// unseeded randomness. Timestamps come from Clock (seeded from
// MAKEFUN_TRIAL_NOW / MAKEFUN_TRIAL_SEED when present, else fixed
// constants) plus the global creation sequence; request ids come from a
// monotonic counter. Orderings are deterministic: repos/issues/labels in
// creation order, refs sorted by name, PR files sorted by path.
//
// Performance shape (v2): Timestamp results are memoized in the Clock
// (the value is a pure function of the sequence number); ObjectSHA builds
// its "<type> <len>\0" header with direct byte writes and hashes once;
// PutObjectsBatch stores a whole unpacked pack under a single write lock
// using SHAs the caller already computed; each Repo carries a generation
// counter plus a cached immutable snapshot, so the git layer can reuse one
// consistent refs+objects view across many requests and only rebuilds it
// when a push or contents write actually changes the repo.

package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scenario constants, identical in every trial.
const (
	// ViewerLogin is the login of the token owner.
	ViewerLogin = "adaiversen"
	// ViewerID is the token owner's user id.
	ViewerID = 1000
	// ViewerEmail is the token owner's email.
	ViewerEmail = "adaiversen@example.invalid"
	// StrangerLogin is another user whose repos must 404, never 403.
	StrangerLogin = "olgabauer"
	// OrgLogin is the scenario organisation.
	OrgLogin = "faint-meadow-org"
	// DefaultBranch is the default branch of every repo.
	DefaultBranch = "main"
	// ZeroSHA is the all-zero object id (unborn/absent ref).
	ZeroSHA = "0000000000000000000000000000000000000000"
)

// DefaultSeed is the fixed logical seed used when MAKEFUN_TRIAL_SEED is unset.
const DefaultSeed uint64 = 0x6a09e667f3bcc909

// DefaultNow is the fixed logical epoch used when MAKEFUN_TRIAL_NOW is unset
// (2025-01-01T00:00:00Z, the scenario epoch).
var DefaultNow = time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)

// Clock is the store's logical clock. It never reads the wall clock.
// Timestamp is a pure function of the sequence number, so results are
// memoized: the same seq always renders the same string.
type Clock struct {
	base time.Time
	seed uint64
	mu   sync.RWMutex
	memo map[uint64]string
}

// NewClock builds a Clock from MAKEFUN_TRIAL_NOW / MAKEFUN_TRIAL_SEED when
// present, else from the fixed defaults. MAKEFUN_TRIAL_NOW accepts RFC3339
// or unix seconds; MAKEFUN_TRIAL_SEED accepts decimal or 0x-prefixed hex.
func NewClock() *Clock {
	c := &Clock{base: DefaultNow, seed: DefaultSeed}
	if v := os.Getenv("MAKEFUN_TRIAL_NOW"); v != "" {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
			c.base = t.UTC()
		} else if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			c.base = time.Unix(n, 0).UTC()
		}
	}
	if v := os.Getenv("MAKEFUN_TRIAL_SEED"); v != "" {
		if n, err := strconv.ParseUint(strings.TrimSpace(v), 0, 64); err == nil {
			c.seed = n
		}
	}
	return c
}

// Base returns the clock's epoch.
func (c *Clock) Base() time.Time { return c.base }

// Seed returns the clock's seed.
func (c *Clock) Seed() uint64 { return c.seed }

// Timestamp renders a deterministic RFC3339 timestamp for a creation
// sequence number: epoch + seq seconds. The result is memoized; the clock
// never advances, so a seq maps to exactly one string for the trial.
// The memo is read under a shared lock and formatted outside it, so the
// read workload's per-request timestamp lookups never serialize.
func (c *Clock) Timestamp(seq uint64) string {
	c.mu.RLock()
	if rendered, ok := c.memo[seq]; ok {
		c.mu.RUnlock()
		return rendered
	}
	c.mu.RUnlock()
	rendered := c.base.Add(time.Duration(seq) * time.Second).UTC().Format(time.RFC3339)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.memo == nil {
		c.memo = make(map[uint64]string)
	}
	if prev, ok := c.memo[seq]; ok {
		return prev
	}
	c.memo[seq] = rendered
	return rendered
}

// ObjectType is a git object type.
type ObjectType int

const (
	ObjBlob ObjectType = iota + 1
	ObjTree
	ObjCommit
	ObjTag
)

func (t ObjectType) String() string {
	switch t {
	case ObjBlob:
		return "blob"
	case ObjTree:
		return "tree"
	case ObjCommit:
		return "commit"
	case ObjTag:
		return "tag"
	default:
		return "unknown"
	}
}

// ParseObjectType parses a git object type name.
func ParseObjectType(s string) (ObjectType, bool) {
	switch s {
	case "blob":
		return ObjBlob, true
	case "tree":
		return ObjTree, true
	case "commit":
		return ObjCommit, true
	case "tag":
		return ObjTag, true
	}
	return 0, false
}

// ObjectSHA computes the git SHA-1 id of an object: SHA-1("<type> <len>\0" +
// raw). The header is assembled with direct byte writes into a stack
// buffer — no fmt, no allocation — and the object is hashed in a single
// pass: the header bytes, then the raw payload.
func ObjectSHA(typ ObjectType, raw []byte) string {
	var head [40]byte
	n := copy(head[:], typ.String())
	head[n] = ' '
	n++
	digits := strconv.AppendInt(head[n:n], int64(len(raw)), 10)
	n += len(digits)
	head[n] = 0
	n++
	h := sha1.New()
	h.Write(head[:n])
	h.Write(raw)
	var out [40]byte
	hex.Encode(out[:], h.Sum(nil))
	return string(out[:])
}

// TreeEntry is one entry of a parsed git tree object.
type TreeEntry struct {
	Mode string // e.g. "100644" for blobs, "40000" for trees
	Name string
	SHA  string // hex object id of the entry
}

// ParsedCommit is the parsed header form of a commit object.
type ParsedCommit struct {
	Tree      string
	Parents   []string
	Author    string
	Committer string
	Message   string
}

// ParsedTag is the parsed header form of an annotated tag object.
type ParsedTag struct {
	Object  string
	Type    string
	Tag     string
	Tagger  string
	Message string
}

// GitObject is one stored git object. Raw is the exact object payload bytes
// (without the "<type> <len>\0" header) and is what must be served back for
// byte-exact round-trips. Exactly one of Tree/Commit/Tag is set, matching Type.
type GitObject struct {
	SHA    string
	Type   ObjectType
	Raw    []byte
	Tree   []TreeEntry   // set when Type == ObjTree
	Commit *ParsedCommit // set when Type == ObjCommit
	Tag    *ParsedTag    // set when Type == ObjTag
}

// parseTree decodes the binary tree format: "<mode> <name>\0<20-byte sha>"
// repeated. A malformed tail stops the scan; the entries decoded so far
// are kept.
func parseTree(raw []byte) []TreeEntry {
	var entries []TreeEntry
	pos := 0
	for pos < len(raw) {
		sp := bytes.IndexByte(raw[pos:], ' ')
		if sp < 0 {
			break
		}
		mode := raw[pos : pos+sp]
		rest := raw[pos+sp+1:]
		nul := bytes.IndexByte(rest, 0)
		if nul < 0 || nul+21 > len(rest) {
			break
		}
		entries = append(entries, TreeEntry{
			Mode: string(mode),
			Name: string(rest[:nul]),
			SHA:  hex.EncodeToString(rest[nul+1 : nul+21]),
		})
		pos += sp + 1 + nul + 21
	}
	return entries
}

// forEachHeaderLine splits a commit/tag payload at the blank line and calls
// fn for each "key value" header line, skipping blanks and continuation
// lines. It returns the message body (everything after the blank line).
func forEachHeaderLine(raw []byte, fn func(key, val string)) string {
	head, body, _ := strings.Cut(string(raw), "\n\n")
	for _, line := range strings.Split(head, "\n") {
		if line == "" || line[0] == ' ' {
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		fn(key, val)
	}
	return body
}

// parseCommit decodes a commit object's headers and message.
func parseCommit(raw []byte) *ParsedCommit {
	pc := &ParsedCommit{}
	pc.Message = forEachHeaderLine(raw, func(key, val string) {
		switch key {
		case "tree":
			pc.Tree = val
		case "parent":
			pc.Parents = append(pc.Parents, val)
		case "author":
			pc.Author = val
		case "committer":
			pc.Committer = val
		}
	})
	return pc
}

// parseTag decodes an annotated tag object's headers and message.
func parseTag(raw []byte) *ParsedTag {
	pt := &ParsedTag{}
	pt.Message = forEachHeaderLine(raw, func(key, val string) {
		switch key {
		case "object":
			pt.Object = val
		case "type":
			pt.Type = val
		case "tag":
			pt.Tag = val
		case "tagger":
			pt.Tagger = val
		}
	})
	return pt
}

// Repo is one repository: identity, git objects, refs, issues, PRs, labels.
// gen counts git mutations (object or ref changes) and snap is the cached
// immutable snapshot for that generation; both are guarded by the Store
// lock and are never read or written outside Store methods.
type Repo struct {
	ID            int64
	Owner         string
	Name          string
	Description   string
	Private       bool
	DefaultBranch string
	Seq           uint64 // global creation sequence

	Objects map[string]*GitObject // SHA-1 hex -> object
	Refs    map[string]string     // full ref name ("refs/heads/main") -> SHA-1 hex

	Issues     map[int]*Issue
	IssueOrder []int
	PRs        map[int]*PullRequest
	PROrder    []int
	// NextNumber is the shared issue/PR numbering sequence (GitHub shares one
	// sequence for issues and pull requests within a repo).
	NextNumber int

	Labels     map[string]*Label
	LabelOrder []string

	gen  uint64
	snap *RepoSnapshot
}

// RepoSnapshot is a consistent, immutable view of a repo's git state at one
// generation: refs (plus their sorted names) and the object map, both
// copied once when the snapshot was built. GitObjects are immutable once
// stored, so sharing their pointers is safe; the maps themselves are never
// mutated after the snapshot is built. The git layer reuses this handle
// across requests instead of copying the object map on every call.
type RepoSnapshot struct {
	Generation uint64
	Refs       map[string]string
	RefNames   []string // sorted
	Objects    map[string]*GitObject
}

// Label is a repo label. An issue may only carry labels that exist.
type Label struct {
	Name  string
	Color string
	Seq   uint64
}

// Comment is an issue comment.
type Comment struct {
	ID     int64
	Body   string
	Author string
	Seq    uint64
}

// Issue is a repo issue.
type Issue struct {
	Number   int
	Title    string
	Body     string
	State    string   // "open" or "closed"
	Labels   []string // label names, in the order supplied at creation
	Comments []*Comment
	Seq      uint64
}

// PRFile is one changed file in a pull request diff.
type PRFile struct {
	Filename  string
	Status    string // "added", "modified", or "removed"
	Additions int
	Deletions int
	Changes   int
}

// PullRequest is a repo pull request.
type PullRequest struct {
	Number         int
	Title          string
	Body           string
	State          string // "open" or "closed"
	HeadRef        string // head branch name, e.g. "feature/x"
	BaseRef        string // base branch name, e.g. "main"
	HeadSHA        string // head branch tip at creation
	BaseSHA        string // base branch tip at creation
	Merged         bool
	MergedAt       string   // RFC3339, "" until merged
	MergeCommitSHA string   // "" until merged
	Files          []PRFile // diff of head tip vs base tip at creation, sorted by path
	Seq            uint64
}

// RefEntry is one ref for listings, sorted by name.
type RefEntry struct {
	Name string
	SHA  string
}

var (
	// ErrRepoExists is returned when creating a repo that already exists.
	ErrRepoExists = errors.New("repository already exists")
	// ErrNotFound is returned when an issue, PR, or comment target is missing.
	ErrNotFound = errors.New("not found")
	// ErrUnknownLabel is returned when an issue names a label that does not exist.
	ErrUnknownLabel = errors.New("unknown label")
	// ErrRefNotFound is returned when a named ref does not exist.
	ErrRefNotFound = errors.New("ref not found")
	// ErrNonFastForward is returned when a ref update is not a fast-forward.
	ErrNonFastForward = errors.New("non-fast-forward")
	// ErrStaleOld is returned when a ref update's old id does not match the current tip.
	ErrStaleOld = errors.New("stale old object id")
)

// Store is the single shared in-memory store for all surfaces.
type Store struct {
	mu            sync.RWMutex
	clock         *Clock
	seq           uint64
	reqID         atomic.Uint64
	nextRepoID    int64
	nextCommentID int64
	repos         map[string]*Repo
	reposByID     map[int64]*Repo
	repoOrder     []string // RepoKeys in creation order
}

// NewStore creates an empty store with a clock seeded from the environment.
func NewStore() *Store {
	return &Store{
		clock:         NewClock(),
		nextRepoID:    1,
		nextCommentID: 1,
		repos:         make(map[string]*Repo),
		reposByID:     make(map[int64]*Repo),
	}
}

// RLock acquires the store read lock (see the locking discipline above).
func (s *Store) RLock() { s.mu.RLock() }

// RUnlock releases the store read lock.
func (s *Store) RUnlock() { s.mu.RUnlock() }

// Lock acquires the store write lock.
func (s *Store) Lock() { s.mu.Lock() }

// Unlock releases the store write lock.
func (s *Store) Unlock() { s.mu.Unlock() }

// Clock returns the store's logical clock.
func (s *Store) Clock() *Clock { return s.clock }

// Timestamp renders a deterministic RFC3339 timestamp for a sequence number.
func (s *Store) Timestamp(seq uint64) string { return s.clock.Timestamp(seq) }

// NextRequestID returns the next deterministic request id ("req-<n>").
func (s *Store) NextRequestID() string {
	return "req-" + strconv.FormatUint(s.reqID.Add(1), 10)
}

// NextSeq returns the next value of the global creation sequence counter.
func (s *Store) NextSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextSeqLocked()
}

func (s *Store) nextSeqLocked() uint64 {
	s.seq++
	return s.seq
}

// RepoKey is the store key for a repo: "owner/name".
func RepoKey(owner, name string) string { return owner + "/" + name }

// BranchRef returns the full ref name for a branch.
func BranchRef(name string) string { return "refs/heads/" + name }

// TagRef returns the full ref name for a tag.
func TagRef(name string) string { return "refs/tags/" + name }

// noteGitChangedLocked records a git mutation: the generation advances and
// the cached snapshot is dropped, so the next Snapshot rebuilds. Callers
// hold the write lock and call this only when objects or refs actually
// changed.
func (s *Store) noteGitChangedLocked(r *Repo) {
	r.gen++
	r.snap = nil
}

// Generation returns the repo's current git generation: it advances on
// every object or ref mutation and never moves otherwise. The pack cache
// keys on it, so a pack built at one generation is never reused after
// the repo changes.
func (s *Store) Generation(r *Repo) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return r.gen
}

// Snapshot returns the repo's cached immutable snapshot, building it on
// first use after a git mutation. Repeated calls at the same generation
// return the same pointer with no map copying. The snapshot's maps must
// never be mutated by callers.
func (s *Store) Snapshot(r *Repo) *RepoSnapshot {
	s.mu.RLock()
	if snap := r.snap; snap != nil {
		s.mu.RUnlock()
		return snap
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.snap != nil {
		return r.snap
	}
	refs := make(map[string]string, len(r.Refs))
	names := make([]string, 0, len(r.Refs))
	for name, sha := range r.Refs {
		refs[name] = sha
		names = append(names, name)
	}
	sort.Strings(names)
	objs := make(map[string]*GitObject, len(r.Objects))
	for sha, obj := range r.Objects {
		objs[sha] = obj
	}
	snap := &RepoSnapshot{Generation: r.gen, Refs: refs, RefNames: names, Objects: objs}
	r.snap = snap
	return snap
}

// CreateRepo creates a repo with the next repo id and default branch "main".
// It returns ErrRepoExists when owner/name already exists.
func (s *Store) CreateRepo(owner, name, description string, private bool) (*Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := RepoKey(owner, name)
	if _, ok := s.repos[key]; ok {
		return nil, ErrRepoExists
	}
	r := &Repo{
		ID:            s.nextRepoID,
		Owner:         owner,
		Name:          name,
		Description:   description,
		Private:       private,
		DefaultBranch: DefaultBranch,
		Seq:           s.nextSeqLocked(),
		Objects:       make(map[string]*GitObject),
		Refs:          make(map[string]string),
		Issues:        make(map[int]*Issue),
		PRs:           make(map[int]*PullRequest),
		NextNumber:    1,
		Labels:        make(map[string]*Label),
	}
	s.nextRepoID++
	s.repos[key] = r
	s.reposByID[r.ID] = r
	s.repoOrder = append(s.repoOrder, key)
	return r, nil
}

// GetRepo returns the repo at owner/name, if it exists.
func (s *Store) GetRepo(owner, name string) (*Repo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.repos[RepoKey(owner, name)]
	return r, ok
}

// GetRepoByID returns the repo with the given id, if it exists.
func (s *Store) GetRepoByID(id int64) (*Repo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reposByID[id]
	return r, ok
}

// ListRepos returns the owner's repos in creation order.
func (s *Store) ListRepos(owner string) []*Repo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Repo
	for _, key := range s.repoOrder {
		if r := s.repos[key]; r.Owner == owner {
			out = append(out, r)
		}
	}
	return out
}

// DeleteRepo removes a repo. It reports whether one existed.
func (s *Store) DeleteRepo(owner, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := RepoKey(owner, name)
	r, ok := s.repos[key]
	if !ok {
		return false
	}
	delete(s.repos, key)
	delete(s.reposByID, r.ID)
	for i, k := range s.repoOrder {
		if k == key {
			s.repoOrder = append(s.repoOrder[:i], s.repoOrder[i+1:]...)
			break
		}
	}
	return true
}

// SetRepoDescription updates a repo's description.
func (s *Store) SetRepoDescription(r *Repo, description string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Description = description
}

// buildGitObject parses one object payload into its stored form. sha must
// already be the object's id (computed by the caller or by ObjectSHA).
func buildGitObject(sha string, typ ObjectType, raw []byte) *GitObject {
	obj := &GitObject{SHA: sha, Type: typ, Raw: raw}
	switch typ {
	case ObjTree:
		obj.Tree = parseTree(raw)
	case ObjCommit:
		obj.Commit = parseCommit(raw)
	case ObjTag:
		obj.Tag = parseTag(raw)
	}
	return obj
}

// PutObject stores an object, computing its SHA-1 id. Storing an object that
// already exists is a no-op returning the stored object.
func (s *Store) PutObject(r *Repo, typ ObjectType, raw []byte) *GitObject {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putObjectLocked(r, typ, raw)
}

func (s *Store) putObjectLocked(r *Repo, typ ObjectType, raw []byte) *GitObject {
	sha := ObjectSHA(typ, raw)
	if existing, ok := r.Objects[sha]; ok {
		return existing
	}
	obj := buildGitObject(sha, typ, raw)
	r.Objects[sha] = obj
	s.noteGitChangedLocked(r)
	return obj
}

// PutObjectsBatch stores a whole unpacked pack under one write lock. The
// caller supplies each object's SHA, already computed once while parsing
// the pack (see ParsePack), so no object is hashed a second time here; an
// empty SHA falls back to computing it. Objects already in the store are
// returned as-is. The returned slice lines up with the input: out[i] is
// the stored object for objs[i] (nil for a nil input entry). The repo
// generation advances once, and only when at least one object was new.
func (s *Store) PutObjectsBatch(r *Repo, objs []*PackObject) []*GitObject {
	if len(objs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*GitObject, len(objs))
	changed := false
	for i, po := range objs {
		if po == nil {
			continue
		}
		sha := po.SHA
		if sha == "" {
			sha = ObjectSHA(po.Type, po.Raw)
		}
		if existing, ok := r.Objects[sha]; ok {
			out[i] = existing
			continue
		}
		obj := buildGitObject(sha, po.Type, po.Raw)
		r.Objects[sha] = obj
		out[i] = obj
		changed = true
	}
	if changed {
		s.noteGitChangedLocked(r)
	}
	return out
}

// GetObject returns the object with the given SHA-1 hex, if stored.
func (s *Store) GetObject(r *Repo, sha string) (*GitObject, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	obj, ok := r.Objects[sha]
	return obj, ok
}

// GetRef returns the tip SHA-1 of a full ref name, if the ref exists.
func (s *Store) GetRef(r *Repo, ref string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sha, ok := r.Refs[ref]
	return sha, ok
}

// ListRefs returns all refs sorted by name. The order comes from the
// repo's cached snapshot, so repeated listings at one generation do not
// re-sort; the snapshot is taken with no lock held here.
func (s *Store) ListRefs(r *Repo) []RefEntry {
	snap := s.Snapshot(r)
	out := make([]RefEntry, 0, len(snap.RefNames))
	for _, name := range snap.RefNames {
		out = append(out, RefEntry{Name: name, SHA: snap.Refs[name]})
	}
	return out
}

// SetRef unconditionally sets a ref (used by the refs API and merges).
func (s *Store) SetRef(r *Repo, ref, sha string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Refs[ref] = sha
	s.noteGitChangedLocked(r)
}

// DeleteRef removes a ref. It reports whether one existed.
func (s *Store) DeleteRef(r *Repo, ref string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := r.Refs[ref]; !ok {
		return false
	}
	delete(r.Refs, ref)
	s.noteGitChangedLocked(r)
	return true
}

// UpdateRefChecked applies one receive-pack ref command with strict
// fast-forward rules: a create requires old == zero and no existing ref; an
// update requires old == current tip and new a descendant of old; a delete
// (new == zero) requires the ref to exist and old to match (or be zero).
// It returns ErrStaleOld, ErrNonFastForward, or ErrRefNotFound on refusal
// and leaves the ref untouched.
func (s *Store) UpdateRefChecked(r *Repo, ref, oldSHA, newSHA string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := r.Refs[ref]
	if newSHA == ZeroSHA {
		if !exists {
			return ErrRefNotFound
		}
		if oldSHA != ZeroSHA && oldSHA != current {
			return ErrStaleOld
		}
		delete(r.Refs, ref)
		s.noteGitChangedLocked(r)
		return nil
	}
	if !exists {
		if oldSHA != ZeroSHA {
			return ErrStaleOld
		}
		r.Refs[ref] = newSHA
		s.noteGitChangedLocked(r)
		return nil
	}
	if oldSHA != current {
		return ErrStaleOld
	}
	if !s.isAncestorLocked(r, current, newSHA) {
		return ErrNonFastForward
	}
	r.Refs[ref] = newSHA
	s.noteGitChangedLocked(r)
	return nil
}

// IsAncestor reports whether ancestor equals descendant or is reachable from
// descendant by following parent links (tag objects are peeled first).
func (s *Store) IsAncestor(r *Repo, ancestor, descendant string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isAncestorLocked(r, ancestor, descendant)
}

// isAncestorLocked is the lock-held ancestor walk: breadth-first from the
// peeled descendant, parents in stored order, with a visited set. The
// common bench case (parent == old tip) answers at the first level.
func (s *Store) isAncestorLocked(r *Repo, ancestor, descendant string) bool {
	if ancestor == descendant {
		return true
	}
	start := s.peelLocked(r, descendant)
	if ancestor == start {
		return true
	}
	seen := map[string]bool{start: true}
	queue := []string{start}
	for head := 0; head < len(queue); head++ {
		obj := r.Objects[queue[head]]
		if obj == nil || obj.Commit == nil {
			continue
		}
		for _, p := range obj.Commit.Parents {
			if p == ancestor {
				return true
			}
			if !seen[p] {
				seen[p] = true
				queue = append(queue, p)
			}
		}
	}
	return false
}

// PeelToCommit follows annotated tag objects to the commit they point at
// (transitively, up to 16 hops). Non-tag ids pass through unchanged.
func (s *Store) PeelToCommit(r *Repo, sha string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peelLocked(r, sha)
}

func (s *Store) peelLocked(r *Repo, sha string) string {
	for i := 0; i < 16; i++ {
		obj := r.Objects[sha]
		if obj == nil || obj.Type != ObjTag || obj.Tag == nil {
			return sha
		}
		sha = obj.Tag.Object
	}
	return sha
}

// CommitTreeSHA returns the root tree SHA-1 of a commit (tags peeled).
func (s *Store) CommitTreeSHA(r *Repo, commitSHA string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.commitTreeLocked(r, commitSHA)
}

func (s *Store) commitTreeLocked(r *Repo, commitSHA string) (string, bool) {
	sha := s.peelLocked(r, commitSHA)
	obj := r.Objects[sha]
	if obj == nil || obj.Commit == nil {
		return "", false
	}
	return obj.Commit.Tree, true
}

// treeFlattener walks one tree recursively, collecting path -> blob SHA-1
// for every blob, skipping cycles via the per-path ancestor set and
// stopping past depth 64.
type treeFlattener struct {
	r    *Repo
	out  map[string]string
	seen map[string]bool
}

func (w *treeFlattener) walk(treeSHA, prefix string, depth int) {
	if depth > 64 || w.seen[treeSHA] {
		return
	}
	w.seen[treeSHA] = true
	defer delete(w.seen, treeSHA)
	obj := w.r.Objects[treeSHA]
	if obj == nil || obj.Type != ObjTree {
		return
	}
	for _, e := range obj.Tree {
		p := prefix + e.Name
		if e.Mode == "40000" {
			w.walk(e.SHA, p+"/", depth+1)
		} else {
			w.out[p] = e.SHA
		}
	}
}

// FlattenTree returns path -> blob SHA-1 for every blob reachable from a
// tree, recursing into subtrees. Missing trees yield an empty map.
func (s *Store) FlattenTree(r *Repo, treeSHA string) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string)
	w := &treeFlattener{r: r, out: out, seen: make(map[string]bool)}
	w.walk(treeSHA, "", 0)
	return out
}

// MergeBase returns the nearest common ancestor of two commits (tags peeled),
// or "" when they share no history. Ties break by breadth-first order,
// parents in stored order.
func (s *Store) MergeBase(r *Repo, a, b string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a = s.peelLocked(r, a)
	b = s.peelLocked(r, b)
	distA := map[string]int{a: 0}
	queue := []string{a}
	for head := 0; head < len(queue); head++ {
		obj := r.Objects[queue[head]]
		if obj == nil || obj.Commit == nil {
			continue
		}
		for _, p := range obj.Commit.Parents {
			if _, ok := distA[p]; !ok {
				distA[p] = distA[queue[head]] + 1
				queue = append(queue, p)
			}
		}
	}
	seen := map[string]bool{b: true}
	queue = []string{b}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		if _, ok := distA[cur]; ok {
			return cur
		}
		obj := r.Objects[cur]
		if obj == nil || obj.Commit == nil {
			continue
		}
		for _, p := range obj.Commit.Parents {
			if !seen[p] {
				seen[p] = true
				queue = append(queue, p)
			}
		}
	}
	return ""
}

// DiffFiles diffs the trees of two commits (tags peeled) and returns the
// changed files sorted by path. A missing/unknown commit diffs as an empty
// tree. Additions/deletions are blob line counts (a changed file counts all
// lines of the new blob as additions and all lines of the old blob as
// deletions); only non-negativity and additions >= 1 for added files are
// graded.
func (s *Store) DiffFiles(r *Repo, baseCommitSHA, headCommitSHA string) []PRFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.diffFilesLocked(r, baseCommitSHA, headCommitSHA)
}

func (s *Store) diffFilesLocked(r *Repo, baseCommitSHA, headCommitSHA string) []PRFile {
	base := make(map[string]string)
	if tree, ok := s.commitTreeLocked(r, baseCommitSHA); ok {
		w := &treeFlattener{r: r, out: base, seen: make(map[string]bool)}
		w.walk(tree, "", 0)
	}
	head := make(map[string]string)
	if tree, ok := s.commitTreeLocked(r, headCommitSHA); ok {
		w := &treeFlattener{r: r, out: head, seen: make(map[string]bool)}
		w.walk(tree, "", 0)
	}
	return diffFileMaps(r, base, head)
}

func diffFileMaps(r *Repo, base, head map[string]string) []PRFile {
	names := make(map[string]bool, len(base)+len(head))
	for n := range base {
		names[n] = true
	}
	for n := range head {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	var out []PRFile
	for _, name := range sorted {
		bSHA, inBase := base[name]
		hSHA, inHead := head[name]
		switch {
		case inHead && !inBase:
			n := countLines(blobBytes(r, hSHA))
			out = append(out, PRFile{Filename: name, Status: "added", Additions: n, Changes: n})
		case inBase && !inHead:
			n := countLines(blobBytes(r, bSHA))
			out = append(out, PRFile{Filename: name, Status: "removed", Deletions: n, Changes: n})
		case bSHA != hSHA:
			a := countLines(blobBytes(r, hSHA))
			d := countLines(blobBytes(r, bSHA))
			out = append(out, PRFile{Filename: name, Status: "modified", Additions: a, Deletions: d, Changes: a + d})
		}
	}
	return out
}

func blobBytes(r *Repo, sha string) []byte {
	if obj := r.Objects[sha]; obj != nil {
		return obj.Raw
	}
	return nil
}

// countLines counts newline-terminated lines, plus a final unterminated
// line when the blob does not end in "\n".
func countLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := bytes.Count(b, []byte("\n"))
	if b[len(b)-1] != '\n' {
		n++
	}
	return n
}

// CreateLabel creates a label, or returns the existing one with the same name.
func (s *Store) CreateLabel(r *Repo, name, color string) *Label {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := r.Labels[name]; ok {
		return existing
	}
	l := &Label{Name: name, Color: color, Seq: s.nextSeqLocked()}
	r.Labels[name] = l
	r.LabelOrder = append(r.LabelOrder, name)
	return l
}

// GetLabel returns the label with the given name, if it exists.
func (s *Store) GetLabel(r *Repo, name string) (*Label, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := r.Labels[name]
	return l, ok
}

// ListLabels returns the repo's labels in creation order.
func (s *Store) ListLabels(r *Repo) []*Label {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Label, 0, len(r.LabelOrder))
	for _, name := range r.LabelOrder {
		out = append(out, r.Labels[name])
	}
	return out
}

// CreateIssue creates an open issue with the next shared number. Every named
// label must already exist, else ErrUnknownLabel is returned and nothing is
// created.
func (s *Store) CreateIssue(r *Repo, title, body string, labels []string) (*Issue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range labels {
		if _, ok := r.Labels[name]; !ok {
			return nil, ErrUnknownLabel
		}
	}
	n := r.NextNumber
	r.NextNumber++
	iss := &Issue{
		Number: n,
		Title:  title,
		Body:   body,
		State:  "open",
		Labels: append([]string(nil), labels...),
		Seq:    s.nextSeqLocked(),
	}
	r.Issues[n] = iss
	r.IssueOrder = append(r.IssueOrder, n)
	return iss, nil
}

// GetIssue returns the issue with the given number, if it exists.
func (s *Store) GetIssue(r *Repo, number int) (*Issue, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	iss, ok := r.Issues[number]
	return iss, ok
}

// ListIssues returns the repo's issues in creation (number) order.
func (s *Store) ListIssues(r *Repo) []*Issue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Issue, 0, len(r.IssueOrder))
	for _, n := range r.IssueOrder {
		out = append(out, r.Issues[n])
	}
	return out
}

// SetIssueState sets an issue's state ("open" or "closed").
func (s *Store) SetIssueState(r *Repo, number int, state string) (*Issue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	iss, ok := r.Issues[number]
	if !ok {
		return nil, ErrNotFound
	}
	iss.State = state
	return iss, nil
}

// AddComment appends a comment to an issue.
func (s *Store) AddComment(r *Repo, number int, body, author string) (*Comment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	iss, ok := r.Issues[number]
	if !ok {
		return nil, ErrNotFound
	}
	c := &Comment{ID: s.nextCommentID, Body: body, Author: author, Seq: s.nextSeqLocked()}
	s.nextCommentID++
	iss.Comments = append(iss.Comments, c)
	return c, nil
}

// ListComments returns a copy of an issue's comment list in creation order.
func (s *Store) ListComments(r *Repo, number int) ([]*Comment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	iss, ok := r.Issues[number]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]*Comment(nil), iss.Comments...), nil
}

// CreatePullRequest opens a pull request between two existing branches. Head
// and base SHAs are the branch tips at creation; Files is the diff of head
// tip vs base tip. It returns ErrRefNotFound when either branch is missing.
func (s *Store) CreatePullRequest(r *Repo, title, body, headRef, baseRef string) (*PullRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	headSHA, ok := r.Refs[BranchRef(headRef)]
	if !ok {
		return nil, ErrRefNotFound
	}
	baseSHA, ok := r.Refs[BranchRef(baseRef)]
	if !ok {
		return nil, ErrRefNotFound
	}
	n := r.NextNumber
	r.NextNumber++
	pr := &PullRequest{
		Number:  n,
		Title:   title,
		Body:    body,
		State:   "open",
		HeadRef: headRef,
		BaseRef: baseRef,
		HeadSHA: headSHA,
		BaseSHA: baseSHA,
		Seq:     s.nextSeqLocked(),
	}
	pr.Files = s.diffFilesLocked(r, baseSHA, headSHA)
	r.PRs[n] = pr
	r.PROrder = append(r.PROrder, n)
	return pr, nil
}

// GetPullRequest returns the pull request with the given number, if it exists.
func (s *Store) GetPullRequest(r *Repo, number int) (*PullRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pr, ok := r.PRs[number]
	return pr, ok
}

// ListPullRequests returns the repo's pull requests in creation (number) order.
func (s *Store) ListPullRequests(r *Repo) []*PullRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*PullRequest, 0, len(r.PROrder))
	for _, n := range r.PROrder {
		out = append(out, r.PRs[n])
	}
	return out
}

// MarkPRMerged records a squash merge: closed, merged, merge commit SHA, and
// a deterministic merged_at timestamp from the logical clock.
func (s *Store) MarkPRMerged(r *Repo, number int, mergeSHA string) (*PullRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pr, ok := r.PRs[number]
	if !ok {
		return nil, ErrNotFound
	}
	pr.Merged = true
	pr.State = "closed"
	pr.MergeCommitSHA = mergeSHA
	pr.MergedAt = s.clock.Timestamp(s.nextSeqLocked())
	return pr, nil
}

// GlobalID renders an opaque, stable GraphQL global id. The encoding is
// base64url("forge:<kind>:<repoID>:<number>"); it never equals a plain
// databaseId or issue/PR number string.
func GlobalID(kind string, repoID int64, number int) string {
	var raw []byte
	raw = append(raw, "forge:"...)
	raw = append(raw, kind...)
	raw = append(raw, ':')
	raw = strconv.AppendInt(raw, repoID, 10)
	raw = append(raw, ':')
	raw = strconv.AppendInt(raw, int64(number), 10)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// ParseGlobalID decodes a GlobalID. Kinds are "Repository", "Issue", and
// "PullRequest"; number is 0 for repositories.
func ParseGlobalID(id string) (kind string, repoID int64, number int, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", 0, 0, false
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 4 || parts[0] != "forge" {
		return "", 0, 0, false
	}
	rid, err1 := strconv.ParseInt(parts[2], 10, 64)
	num, err2 := strconv.Atoi(parts[3])
	if err1 != nil || err2 != nil {
		return "", 0, 0, false
	}
	return parts[1], rid, num, true
}

// RepoGlobalID returns the global id for a repository.
func RepoGlobalID(r *Repo) string { return GlobalID("Repository", r.ID, 0) }

// IssueGlobalID returns the global id for an issue.
func IssueGlobalID(r *Repo, iss *Issue) string { return GlobalID("Issue", r.ID, iss.Number) }

// PRGlobalID returns the global id for a pull request.
func PRGlobalID(r *Repo, pr *PullRequest) string {
	return GlobalID("PullRequest", r.ID, pr.Number)
}
