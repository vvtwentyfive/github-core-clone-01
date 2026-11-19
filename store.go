package main

import (
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Deterministic clock base: 2025-01-01T00:00:00Z.
const storeClockBaseUnix int64 = 1735689600

// All-zero git object id, used to mean "delete this ref".
const storeZeroOID = "0000000000000000000000000000000000000000"

// Fixed viewer identity: the token owner always has id 1000.
const storeViewerID int64 = 1000

// Sentinel errors. Handlers translate these into HTTP statuses.
var (
	ErrExists         = errors.New("already exists")
	ErrNotFound       = errors.New("not found")
	ErrNonFastForward = errors.New("non-fast-forward update")
	ErrStaleSHA       = errors.New("stale sha")
	ErrUnknownLabel   = errors.New("unknown label")
	ErrUnknownRef     = errors.New("unknown ref")
	ErrAlreadyMerged  = errors.New("already merged")
	ErrConflict       = errors.New("merge conflict")
)

// Object is one stored git object. Only one of Commit, Tree, Tag is set,
// according to Type; blobs and other types leave all three nil.
type Object struct {
	Type   string
	Raw    []byte
	Commit *Commit
	Tree   *Tree
	Tag    *Tag
}

// Commit is the parsed form of a commit object.
type Commit struct {
	Tree      string
	Parents   []string
	Author    string
	Committer string
	Message   string
}

// TreeEntry is one entry of a git tree object.
type TreeEntry struct {
	Mode string
	Name string
	OID  string
}

// Tree is the parsed form of a tree object.
type Tree struct {
	Entries []TreeEntry
}

// Tag is the parsed form of an annotated tag object.
type Tag struct {
	Object  string
	Type    string
	Tag     string
	Tagger  string
	Message string
}

// Label is a repository label.
type Label struct {
	ID          int64
	Name        string
	Color       string
	Description string
}

// Issue is a repository issue.
type Issue struct {
	ID        int64
	Number    int
	Title     string
	Body      string
	State     string
	Labels    []string
	Comments  int
	CreatedAt string
	UpdatedAt string
	Seq       uint64
}

// Pull is a repository pull request.
type Pull struct {
	ID        int64
	Number    int
	Title     string
	Body      string
	State     string
	Head      string
	Base      string
	HeadSHA   string
	BaseSHA   string
	Merged    bool
	MergeSHA  string
	MergedAt  string
	CreatedAt string
	UpdatedAt string
	Seq       uint64
}

// Repo is one repository and everything stored under it.
type Repo struct {
	ID            int64
	Owner         string
	Name          string
	Description   string
	Private       bool
	DefaultBranch string
	CreatedAt     string
	UpdatedAt     string
	Seq           uint64
	Objects       map[string]*Object
	Refs          map[string]string
	Labels        map[string]*Label
	Issues        []*Issue
	Pulls         []*Pull
	NextIssue     int
	NextPull      int
	Generation    uint64
	snapshot      *RepoSnapshot
	packCache     *PackCache
}

// RepoSnapshot is an immutable copy of a repo's refs and objects at one
// generation. It is rebuilt only when the generation has moved.
type RepoSnapshot struct {
	Refs       map[string]string
	Objects    map[string]*Object
	Generation uint64
}

// Store is the whole in-memory forge state, guarded by one lock.
type Store struct {
	mu        sync.RWMutex
	repos     map[string]*Repo
	seq       uint64
	clockMemo map[uint64]string
	token     string
}

// RawObject is an object supplied with its oid already computed, for batch
// insertion without re-hashing.
type RawObject struct {
	Type string
	Raw  []byte
	OID  string
}

// Ref is one named reference and the oid it points at.
type Ref struct {
	Name string
	OID  string
}

// Content is one file read back from the default branch tip tree.
type Content struct {
	Path    string
	Name    string
	BlobOID string
	Data    []byte
	Size    int
}

// NewStore builds an empty store owned by the given bearer token.
func NewStore(token string) *Store {
	return &Store{
		repos:     make(map[string]*Repo),
		clockMemo: make(map[uint64]string),
		token:     token,
	}
}

// Token returns the bearer token that is also the viewer login.
func (s *Store) Token() string {
	return s.token
}

// ViewerLogin returns the login of the token owner, which is the token.
func (s *Store) ViewerLogin() string {
	return s.token
}

// ViewerID returns the fixed id of the token owner.
func (s *Store) ViewerID() int64 {
	return storeViewerID
}

// NextSeq advances the single global sequence and returns the new value.
// The first value handed out is 1.
func (s *Store) NextSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextSeqLocked()
}

// nextSeqLocked advances the sequence; the caller must hold the lock.
func (s *Store) nextSeqLocked() uint64 {
	s.seq++
	return s.seq
}

// Timestamp renders the deterministic timestamp for a sequence value and
// memoizes it, since the clock is a pure function of the sequence.
func (s *Store) Timestamp(seq uint64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.timestampLocked(seq)
}

// timestampLocked renders and memoizes a timestamp; caller holds the lock.
func (s *Store) timestampLocked(seq uint64) string {
	if held, ok := s.clockMemo[seq]; ok {
		return held
	}
	made := time.Unix(storeClockBaseUnix+int64(seq), 0).UTC().Format(time.RFC3339)
	s.clockMemo[seq] = made
	return made
}

// storeRepoKey builds the map key for one repository.
func storeRepoKey(owner, name string) string {
	return owner + "/" + name
}

// storeRefName turns a branch name into its full ref name.
func storeRefName(branch string) string {
	if strings.HasPrefix(branch, "refs/heads/") {
		return branch
	}
	return "refs/heads/" + branch
}

// storeBranchOf returns the default branch name, falling back to main.
func storeBranchOf(r *Repo) string {
	if r.DefaultBranch == "" {
		return "main"
	}
	return r.DefaultBranch
}

// storeSplitPath splits a content path into non-empty segments.
func storeSplitPath(path string) []string {
	raw := strings.Split(path, "/")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// storeDecodeHexOID turns a 40-hex oid into its 20 raw bytes.
func storeDecodeHexOID(oid string) []byte {
	raw, err := hex.DecodeString(oid)
	if err != nil {
		return make([]byte, 20)
	}
	return raw
}

// storeTreeSortKey is the git ordering key for a tree entry: directories
// compare as if their name ended with a slash.
func storeTreeSortKey(e TreeEntry) string {
	if e.Mode == "040000" {
		return e.Name + "/"
	}
	return e.Name
}

// storeEncodeTree serializes tree entries into raw git tree bytes.
func storeEncodeTree(entries []TreeEntry) []byte {
	var out []byte
	for _, e := range entries {
		out = append(out, []byte(e.Mode)...)
		out = append(out, ' ')
		out = append(out, []byte(e.Name)...)
		out = append(out, 0)
		out = append(out, storeDecodeHexOID(e.OID)...)
	}
	return out
}

// storeCommitBytes renders a commit object body. The author and committer
// lines carry the viewer login, its example address, the unix time for the
// sequence value, and a +0000 zone.
func storeCommitBytes(treeOID string, parents []string, login string, unix int64, message string) []byte {
	var b strings.Builder
	b.WriteString("tree ")
	b.WriteString(treeOID)
	b.WriteString("\n")
	for _, parent := range parents {
		b.WriteString("parent ")
		b.WriteString(parent)
		b.WriteString("\n")
	}
	who := login + " " + login + "@example.invalid " + strconv.FormatInt(unix, 10) + " +0000"
	b.WriteString("author ")
	b.WriteString(who)
	b.WriteString("\n")
	b.WriteString("committer ")
	b.WriteString(who)
	b.WriteString("\n\n")
	b.WriteString(message)
	return []byte(b.String())
}

// buildGitObject parses a raw git object into its structured form. Blobs
// and unknown types keep only Type and Raw.
func buildGitObject(typ string, raw []byte) *Object {
	obj := &Object{Type: typ, Raw: raw}
	switch typ {
	case "commit":
		obj.Commit = storeParseCommit(raw)
	case "tree":
		obj.Tree = storeParseTree(raw)
	case "tag":
		obj.Tag = storeParseTag(raw)
	}
	return obj
}

// storeParseCommit parses commit bytes: tree line, parent lines, author
// and committer lines, a blank line, then the message.
func storeParseCommit(raw []byte) *Commit {
	commit := &Commit{}
	text := string(raw)
	head := text
	body := ""
	if cut := strings.Index(text, "\n\n"); cut >= 0 {
		head = text[:cut]
		body = text[cut+2:]
	}
	commit.Message = body
	for _, line := range strings.Split(head, "\n") {
		switch {
		case strings.HasPrefix(line, "tree "):
			commit.Tree = strings.TrimPrefix(line, "tree ")
		case strings.HasPrefix(line, "parent "):
			commit.Parents = append(commit.Parents, strings.TrimPrefix(line, "parent "))
		case strings.HasPrefix(line, "author "):
			commit.Author = strings.TrimPrefix(line, "author ")
		case strings.HasPrefix(line, "committer "):
			commit.Committer = strings.TrimPrefix(line, "committer ")
		}
	}
	return commit
}

// storeParseTree parses tree bytes: mode, space, name, NUL, 20 oid bytes,
// repeated until the buffer runs out.
func storeParseTree(raw []byte) *Tree {
	tree := &Tree{}
	pos := 0
	for pos < len(raw) {
		space := -1
		for i := pos; i < len(raw); i++ {
			if raw[i] == ' ' {
				space = i
				break
			}
		}
		if space < 0 {
			break
		}
		mode := string(raw[pos:space])
		nul := -1
		for i := space + 1; i < len(raw); i++ {
			if raw[i] == 0 {
				nul = i
				break
			}
		}
		if nul < 0 || nul+21 > len(raw) {
			break
		}
		name := string(raw[space+1 : nul])
		oid := hex.EncodeToString(raw[nul+1 : nul+21])
		tree.Entries = append(tree.Entries, TreeEntry{Mode: mode, Name: name, OID: oid})
		pos = nul + 21
	}
	return tree
}

// storeParseTag parses annotated tag bytes: object, type, tag and tagger
// header lines, a blank line, then the message.
func storeParseTag(raw []byte) *Tag {
	tag := &Tag{}
	text := string(raw)
	head := text
	body := ""
	if cut := strings.Index(text, "\n\n"); cut >= 0 {
		head = text[:cut]
		body = text[cut+2:]
	}
	tag.Message = body
	for _, line := range strings.Split(head, "\n") {
		switch {
		case strings.HasPrefix(line, "object "):
			tag.Object = strings.TrimPrefix(line, "object ")
		case strings.HasPrefix(line, "type "):
			tag.Type = strings.TrimPrefix(line, "type ")
		case strings.HasPrefix(line, "tag "):
			tag.Tag = strings.TrimPrefix(line, "tag ")
		case strings.HasPrefix(line, "tagger "):
			tag.Tagger = strings.TrimPrefix(line, "tagger ")
		}
	}
	return tag
}

// getRepoLocked looks a repository up by owner and name; caller holds lock.
func (s *Store) getRepoLocked(owner, name string) *Repo {
	return s.repos[storeRepoKey(owner, name)]
}

// CreateRepo creates an empty repository. The name must be free for the
// owner, otherwise ErrExists is returned.
func (s *Store) CreateRepo(owner, name, description string, private bool) (*Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getRepoLocked(owner, name) != nil {
		return nil, ErrExists
	}
	seq := s.nextSeqLocked()
	stamp := s.timestampLocked(seq)
	repo := &Repo{
		ID:            int64(seq),
		Owner:         owner,
		Name:          name,
		Description:   description,
		Private:       private,
		DefaultBranch: "main",
		CreatedAt:     stamp,
		UpdatedAt:     stamp,
		Seq:           seq,
		Objects:       make(map[string]*Object),
		Refs:          make(map[string]string),
		Labels:        make(map[string]*Label),
		Issues:        []*Issue{},
		Pulls:         []*Pull{},
		NextIssue:     1,
		NextPull:      1,
		packCache:     NewPackCache(),
	}
	s.repos[storeRepoKey(owner, name)] = repo
	return repo, nil
}

// GetRepo returns the repository or nil when it does not exist.
func (s *Store) GetRepo(owner, name string) *Repo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getRepoLocked(owner, name)
}

// ListRepos returns the owner's repositories ordered by sequence ascending.
func (s *Store) ListRepos(owner string) []*Repo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*Repo{}
	for _, repo := range s.repos {
		if repo.Owner == owner {
			out = append(out, repo)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// DeleteRepo removes a repository; it reports whether one existed.
func (s *Store) DeleteRepo(owner, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeRepoKey(owner, name)
	if _, ok := s.repos[key]; !ok {
		return false
	}
	delete(s.repos, key)
	return true
}

// UpdateRepo changes a repository description and stamps the update time.
// It reports whether the repository existed.
func (s *Store) UpdateRepo(owner, name, description string) (*Repo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	repo := s.getRepoLocked(owner, name)
	if repo == nil {
		return nil, false
	}
	repo.Description = description
	repo.UpdatedAt = s.timestampLocked(s.nextSeqLocked())
	return repo, true
}

// snapshotLocked returns the cached snapshot when its generation still
// matches, and rebuilds it otherwise; caller holds the lock.
func (s *Store) snapshotLocked(r *Repo) *RepoSnapshot {
	if r.snapshot != nil && r.snapshot.Generation == r.Generation {
		return r.snapshot
	}
	refs := make(map[string]string, len(r.Refs))
	for name, oid := range r.Refs {
		refs[name] = oid
	}
	objects := make(map[string]*Object, len(r.Objects))
	for oid, obj := range r.Objects {
		objects[oid] = obj
	}
	snap := &RepoSnapshot{Refs: refs, Objects: objects, Generation: r.Generation}
	r.snapshot = snap
	return snap
}

// Snapshot returns the cached immutable snapshot for a repository,
// rebuilding it when the generation has moved since it was taken.
func (s *Store) Snapshot(r *Repo) *RepoSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked(r)
}

// putObjectLocked stores one object under its computed oid, parsing it
// once, and bumps the generation only when the object is new.
func (s *Store) putObjectLocked(r *Repo, typ string, raw []byte) string {
	oid := ObjectSHA(typ, raw)
	if _, ok := r.Objects[oid]; ok {
		return oid
	}
	kept := append([]byte(nil), raw...)
	obj := buildGitObject(typ, kept)
	obj.Raw = kept
	r.Objects[oid] = obj
	r.Generation++
	return oid
}

// PutObject stores one object and returns its oid.
func (s *Store) PutObject(r *Repo, typ string, raw []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putObjectLocked(r, typ, raw)
}

// PutObjectsBatch stores many objects under a single lock. Each object
// carries its oid already computed, is parsed once, and the generation
// moves once when at least one object was new.
func (s *Store) PutObjectsBatch(r *Repo, objs []RawObject) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(objs))
	anyNew := false
	for i, item := range objs {
		oid := item.OID
		if oid == "" {
			oid = ObjectSHA(item.Type, item.Raw)
		}
		out[i] = oid
		if _, ok := r.Objects[oid]; ok {
			continue
		}
		kept := append([]byte(nil), item.Raw...)
		obj := buildGitObject(item.Type, kept)
		obj.Raw = kept
		r.Objects[oid] = obj
		anyNew = true
	}
	if anyNew {
		r.Generation++
	}
	return out
}

// GetObject returns the stored object for an oid, or nil.
func (s *Store) GetObject(r *Repo, oid string) *Object {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return r.Objects[oid]
}

// ListRefs returns every reference sorted by name.
func (s *Store) ListRefs(r *Repo) []Ref {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Ref, 0, len(r.Refs))
	for name, oid := range r.Refs {
		out = append(out, Ref{Name: name, OID: oid})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// GetRef returns the oid a reference points at and whether it exists.
func (s *Store) GetRef(r *Repo, name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	oid, ok := r.Refs[name]
	return oid, ok
}

// setRefLocked moves a reference and bumps the generation; caller holds lock.
func (s *Store) setRefLocked(r *Repo, name, oid string) {
	r.Refs[name] = oid
	r.Generation++
}

// SetRef moves a reference and bumps the generation.
func (s *Store) SetRef(r *Repo, name, oid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setRefLocked(r, name, oid)
}

// UpdateRefChecked moves a reference only when the move is a fast-forward.
// The current value must equal oldOID, where an empty oldOID (or the zero
// oid) means the reference must not exist yet. A zero newOID deletes the
// reference without any ancestry check. A new reference also skips the
// ancestry check. Anything else must descend from the old value.
func (s *Store) UpdateRefChecked(r *Repo, name, oldOID, newOID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if oldOID == storeZeroOID {
		oldOID = ""
	}
	current, exists := r.Refs[name]
	if newOID == storeZeroOID {
		if !exists {
			return ErrNotFound
		}
		if oldOID != "" && current != oldOID {
			return ErrNonFastForward
		}
		delete(r.Refs, name)
		r.Generation++
		return nil
	}
	if oldOID == "" {
		if exists {
			return ErrNonFastForward
		}
		s.setRefLocked(r, name, newOID)
		return nil
	}
	if !exists {
		return ErrNotFound
	}
	if current != oldOID {
		return ErrNonFastForward
	}
	if newOID == oldOID {
		return nil
	}
	if !s.isAncestorLocked(r, oldOID, newOID) {
		return ErrNonFastForward
	}
	s.setRefLocked(r, name, newOID)
	return nil
}

// isAncestorLocked reports whether ancestor is reachable from descendant
// by following commit parents. Equal oids count as ancestors, and the
// first parent level is checked before any deeper walk, so a linear
// history resolves in one step. Caller holds the lock.
func (s *Store) isAncestorLocked(r *Repo, ancestor, descendant string) bool {
	if ancestor == "" || descendant == "" {
		return false
	}
	if ancestor == descendant {
		return true
	}
	seen := make(map[string]bool)
	queue := []string{descendant}
	for len(queue) > 0 {
		oid := queue[0]
		queue = queue[1:]
		if seen[oid] {
			continue
		}
		seen[oid] = true
		obj := r.Objects[oid]
		if obj == nil || obj.Commit == nil {
			continue
		}
		for _, parent := range obj.Commit.Parents {
			if parent == ancestor {
				return true
			}
			if !seen[parent] {
				queue = append(queue, parent)
			}
		}
	}
	return false
}

// IsAncestor reports whether ancestor is reachable from descendant.
func (s *Store) IsAncestor(r *Repo, ancestor, descendant string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isAncestorLocked(r, ancestor, descendant)
}

// branchTipLocked returns the tip of a branch; caller holds the lock.
func (s *Store) branchTipLocked(r *Repo, branch string) (string, bool) {
	oid, ok := r.Refs[storeRefName(branch)]
	return oid, ok
}

// BranchTip returns the tip commit of a branch.
func (s *Store) BranchTip(r *Repo, branch string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.branchTipLocked(r, branch)
}

// CreateLabel creates a label; the name must be free in the repository.
func (s *Store) CreateLabel(r *Repo, name, color, description string) (*Label, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := r.Labels[name]; ok {
		return nil, ErrExists
	}
	seq := s.nextSeqLocked()
	label := &Label{ID: int64(seq), Name: name, Color: color, Description: description}
	r.Labels[name] = label
	return label, nil
}

// GetLabel returns a label by name, or nil.
func (s *Store) GetLabel(r *Repo, name string) *Label {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return r.Labels[name]
}

// storeFindIssue returns the issue with the given number, or nil.
func storeFindIssue(r *Repo, number int) *Issue {
	for _, issue := range r.Issues {
		if issue.Number == number {
			return issue
		}
	}
	return nil
}

// CreateIssue opens an issue. Every named label must already exist,
// otherwise ErrUnknownLabel is returned and nothing is created.
func (s *Store) CreateIssue(r *Repo, title, body string, labels []string) (*Issue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range labels {
		if _, ok := r.Labels[name]; !ok {
			return nil, ErrUnknownLabel
		}
	}
	seq := s.nextSeqLocked()
	stamp := s.timestampLocked(seq)
	issue := &Issue{
		ID:        int64(seq),
		Number:    r.NextIssue,
		Title:     title,
		Body:      body,
		State:     "open",
		Labels:    append([]string(nil), labels...),
		Comments:  0,
		CreatedAt: stamp,
		UpdatedAt: stamp,
		Seq:       seq,
	}
	r.NextIssue++
	r.Issues = append(r.Issues, issue)
	return issue, nil
}

// GetIssue returns the issue with the given number, or nil.
func (s *Store) GetIssue(r *Repo, number int) *Issue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return storeFindIssue(r, number)
}

// ListIssues returns issues filtered by state: "open", "closed", or ""
// for all of them, in number ascending order.
func (s *Store) ListIssues(r *Repo, state string) []*Issue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*Issue{}
	for _, issue := range r.Issues {
		if state == "" || issue.State == state {
			out = append(out, issue)
		}
	}
	return out
}

// CloseIssue closes an open issue and stamps the update time. It reports
// whether the issue existed.
func (s *Store) CloseIssue(r *Repo, number int) (*Issue, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	issue := storeFindIssue(r, number)
	if issue == nil {
		return nil, false
	}
	if issue.State != "closed" {
		issue.State = "closed"
		issue.UpdatedAt = s.timestampLocked(s.nextSeqLocked())
	}
	return issue, true
}

// AddComment bumps the comment count of an issue and returns the new
// count; it reports whether the issue existed.
func (s *Store) AddComment(r *Repo, number int, body string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	issue := storeFindIssue(r, number)
	if issue == nil {
		return 0, false
	}
	issue.Comments++
	issue.UpdatedAt = s.timestampLocked(s.nextSeqLocked())
	return issue.Comments, true
}

// storeFindPull returns the pull request with the given number, or nil.
func storeFindPull(r *Repo, number int) *Pull {
	for _, pull := range r.Pulls {
		if pull.Number == number {
			return pull
		}
	}
	return nil
}

// CreatePull opens a pull request. Both head and base must name branches
// that exist in the repository, otherwise ErrUnknownRef is returned.
func (s *Store) CreatePull(r *Repo, title, head, base, body string) (*Pull, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	headSHA, ok := s.branchTipLocked(r, head)
	if !ok {
		return nil, ErrUnknownRef
	}
	baseSHA, ok := s.branchTipLocked(r, base)
	if !ok {
		return nil, ErrUnknownRef
	}
	seq := s.nextSeqLocked()
	stamp := s.timestampLocked(seq)
	pull := &Pull{
		ID:        int64(seq),
		Number:    r.NextPull,
		Title:     title,
		Body:      body,
		State:     "open",
		Head:      head,
		Base:      base,
		HeadSHA:   headSHA,
		BaseSHA:   baseSHA,
		Merged:    false,
		CreatedAt: stamp,
		UpdatedAt: stamp,
		Seq:       seq,
	}
	r.NextPull++
	r.Pulls = append(r.Pulls, pull)
	return pull, nil
}

// GetPull returns the pull request with the given number, or nil.
func (s *Store) GetPull(r *Repo, number int) *Pull {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return storeFindPull(r, number)
}

// MergePull squash-merges an open pull request onto its base branch. The
// merge commit takes the head tip's tree, the base tip as its only parent,
// and a "Merge pull request #N from owner/head" message. The merge is a
// conflict unless the head tip descends from the base tip.
func (s *Store) MergePull(r *Repo, number int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pull := storeFindPull(r, number)
	if pull == nil {
		return "", ErrNotFound
	}
	if pull.Merged || pull.State != "open" {
		return "", ErrAlreadyMerged
	}
	headTip, ok := s.branchTipLocked(r, pull.Head)
	if !ok {
		return "", ErrNotFound
	}
	baseTip, ok := s.branchTipLocked(r, pull.Base)
	if !ok {
		return "", ErrNotFound
	}
	if !s.isAncestorLocked(r, baseTip, headTip) {
		return "", ErrConflict
	}
	headObj := r.Objects[headTip]
	if headObj == nil || headObj.Commit == nil {
		return "", ErrNotFound
	}
	seq := s.nextSeqLocked()
	stamp := s.timestampLocked(seq)
	unix := storeClockBaseUnix + int64(seq)
	message := "Merge pull request #" + strconv.Itoa(pull.Number) + " from " + r.Owner + "/" + pull.Head + "\n\n" + pull.Title + "\n"
	raw := storeCommitBytes(headObj.Commit.Tree, []string{baseTip}, s.token, unix, message)
	mergeSHA := s.putObjectLocked(r, "commit", raw)
	s.setRefLocked(r, storeRefName(pull.Base), mergeSHA)
	pull.Merged = true
	pull.State = "closed"
	pull.MergeSHA = mergeSHA
	pull.MergedAt = stamp
	pull.UpdatedAt = stamp
	r.UpdatedAt = stamp
	return mergeSHA, nil
}

// storeBuildTreeLocked rebuilds the tree at baseTreeOID with one path
// applied: the leaf segment gets blobOID, or is removed when blobOID is
// empty. Intermediate trees are rebuilt the same way, and an empty
// subtree is dropped from its parent. It returns the new tree oid, or ""
// when the tree became empty. Caller holds the lock.
func (s *Store) storeBuildTreeLocked(r *Repo, baseTreeOID string, parts []string, blobOID string) string {
	entries := make(map[string]TreeEntry)
	if baseTreeOID != "" {
		if obj := r.Objects[baseTreeOID]; obj != nil && obj.Tree != nil {
			for _, e := range obj.Tree.Entries {
				entries[e.Name] = e
			}
		}
	}
	if len(parts) == 1 {
		if blobOID == "" {
			delete(entries, parts[0])
		} else {
			entries[parts[0]] = TreeEntry{Mode: "100644", Name: parts[0], OID: blobOID}
		}
	} else {
		subOID := ""
		if e, ok := entries[parts[0]]; ok && e.Mode == "040000" {
			subOID = e.OID
		}
		made := s.storeBuildTreeLocked(r, subOID, parts[1:], blobOID)
		if made == "" {
			delete(entries, parts[0])
		} else {
			entries[parts[0]] = TreeEntry{Mode: "040000", Name: parts[0], OID: made}
		}
	}
	if len(entries) == 0 {
		return ""
	}
	list := make([]TreeEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return storeTreeSortKey(list[i]) < storeTreeSortKey(list[j]) })
	return s.putObjectLocked(r, "tree", storeEncodeTree(list))
}

// writeTreeLocked builds a new root tree from a base tree oid with one
// path set or removed. An empty base oid means the tree starts empty.
func (s *Store) writeTreeLocked(r *Repo, baseTreeOID, path, blobOID string) string {
	parts := storeSplitPath(path)
	if len(parts) == 0 {
		return baseTreeOID
	}
	return s.storeBuildTreeLocked(r, baseTreeOID, parts, blobOID)
}

// contentLocked reads a file from the default branch tip tree; caller
// holds the lock.
func (s *Store) contentLocked(r *Repo, path string) (*Content, bool) {
	tip, ok := s.branchTipLocked(r, storeBranchOf(r))
	if !ok {
		return nil, false
	}
	tipObj := r.Objects[tip]
	if tipObj == nil || tipObj.Commit == nil {
		return nil, false
	}
	treeOID := tipObj.Commit.Tree
	parts := storeSplitPath(path)
	if len(parts) == 0 {
		return nil, false
	}
	for i, part := range parts {
		obj := r.Objects[treeOID]
		if obj == nil || obj.Tree == nil {
			return nil, false
		}
		var found *TreeEntry
		for j := range obj.Tree.Entries {
			if obj.Tree.Entries[j].Name == part {
				found = &obj.Tree.Entries[j]
				break
			}
		}
		if found == nil {
			return nil, false
		}
		if i == len(parts)-1 {
			if found.Mode == "040000" {
				return nil, false
			}
			blob := r.Objects[found.OID]
			if blob == nil {
				return nil, false
			}
			data := append([]byte(nil), blob.Raw...)
			return &Content{Path: path, Name: part, BlobOID: found.OID, Data: data, Size: len(data)}, true
		}
		treeOID = found.OID
	}
	return nil, false
}

// PutContent creates or updates a file on the default branch. The sha
// must match the current blob oid when the file exists, and must be empty
// when it does not; otherwise ErrStaleSHA is returned and nothing is
// written. A fresh blob, tree and commit are made and the branch moves
// to the new commit.
func (s *Store) PutContent(r *Repo, path string, content []byte, message, sha string) (commitSHA, treeSHA string, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	branch := storeBranchOf(r)
	tip, hasTip := s.branchTipLocked(r, branch)
	current, exists := s.contentLocked(r, path)
	if exists {
		if sha != current.BlobOID {
			return "", "", false, ErrStaleSHA
		}
	} else if sha != "" {
		return "", "", false, ErrStaleSHA
	}
	seq := s.nextSeqLocked()
	stamp := s.timestampLocked(seq)
	unix := storeClockBaseUnix + int64(seq)
	blobOID := s.putObjectLocked(r, "blob", content)
	baseTreeOID := ""
	if hasTip {
		if tipObj := r.Objects[tip]; tipObj != nil && tipObj.Commit != nil {
			baseTreeOID = tipObj.Commit.Tree
		}
	}
	treeOID := s.writeTreeLocked(r, baseTreeOID, path, blobOID)
	var parents []string
	if hasTip {
		parents = []string{tip}
	}
	raw := storeCommitBytes(treeOID, parents, s.token, unix, message)
	commitOID := s.putObjectLocked(r, "commit", raw)
	s.setRefLocked(r, storeRefName(branch), commitOID)
	r.UpdatedAt = stamp
	return commitOID, treeOID, !exists, nil
}

// GetContent returns the file at a path on the default branch tip.
func (s *Store) GetContent(r *Repo, path string) (*Content, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.contentLocked(r, path)
}

// DeleteContent removes a file from the default branch. The sha must
// match the current blob oid, otherwise ErrStaleSHA is returned; a
// missing file returns ErrNotFound. A new tree and commit are made and
// the branch moves to the new commit.
func (s *Store) DeleteContent(r *Repo, path, message, sha string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	branch := storeBranchOf(r)
	tip, hasTip := s.branchTipLocked(r, branch)
	if !hasTip {
		return "", ErrNotFound
	}
	current, exists := s.contentLocked(r, path)
	if !exists {
		return "", ErrNotFound
	}
	if sha != current.BlobOID {
		return "", ErrStaleSHA
	}
	seq := s.nextSeqLocked()
	stamp := s.timestampLocked(seq)
	unix := storeClockBaseUnix + int64(seq)
	baseTreeOID := ""
	if tipObj := r.Objects[tip]; tipObj != nil && tipObj.Commit != nil {
		baseTreeOID = tipObj.Commit.Tree
	}
	treeOID := s.writeTreeLocked(r, baseTreeOID, path, "")
	if treeOID == "" {
		treeOID = s.putObjectLocked(r, "tree", []byte{})
	}
	raw := storeCommitBytes(treeOID, []string{tip}, s.token, unix, message)
	commitOID := s.putObjectLocked(r, "commit", raw)
	s.setRefLocked(r, storeRefName(branch), commitOID)
	r.UpdatedAt = stamp
	return commitOID, nil
}
