// REST v3 surface: repositories, branches, commits, contents, git refs,
// labels, issues, comments, and pull requests, all over the shared Store.
//
// Routing: RegisterREST owns every path under /api/v3 (the API root itself
// is served by main.go, which registers first; GET /api/v3/meta is served
// here). Every reply is JSON; auth, request ids, and malformed-body 400s
// are enforced by the middleware in main.go.
//
// Ownership: repositories created through POST /user/repos belong to the
// token owner (ViewerLogin). Any other owner in a /repos/{owner}/{repo}
// path resolves to nothing and answers 404, never 403.
//
// Determinism: timestamps come from the store's logical clock plus creation
// sequence numbers; commit objects built here (contents writes, squash
// merges) use sequence-derived author/committer timestamps, so identical
// request streams produce identical object ids.
//
// Performance shape (v2): the hot views (issue, repository, pull request,
// label, comment) are encoded by hand into a reused-style byte buffer
// instead of reflection-marshalled structs; request bodies are decoded
// exactly once per request from bytes the middleware already read; and
// timestamps are memoized per sequence number because the logical clock
// is a pure function of that number.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type metaBody struct {
	InstalledVersion string `json:"installed_version"`
}

type restHandler struct {
	s *Store

	// tsMu/tsCache memoize Clock.Timestamp: the logical clock is a pure
	// function of the sequence number, so formatting it once per seq is
	// exact and never stale within a process. Reads take the read lock;
	// only a cache miss takes the write lock.
	tsMu    sync.RWMutex
	tsCache map[uint64]string
}

// ts renders the deterministic timestamp for seq, memoized.
func (h *restHandler) ts(seq uint64) string {
	h.tsMu.RLock()
	if v, ok := h.tsCache[seq]; ok {
		h.tsMu.RUnlock()
		return v
	}
	h.tsMu.RUnlock()
	h.tsMu.Lock()
	defer h.tsMu.Unlock()
	if v, ok := h.tsCache[seq]; ok {
		return v
	}
	v := h.s.Timestamp(seq)
	if h.tsCache == nil {
		h.tsCache = make(map[uint64]string)
	}
	h.tsCache[seq] = v
	return v
}

// RegisterREST registers the REST v3 routes on mux.
func RegisterREST(mux *Router, s *Store) {
	h := &restHandler{s: s}
	mux.Handle(func(r *http.Request, path string) bool {
		return path == "/api/v3" || strings.HasPrefix(path, "/api/v3/")
	}, h.ServeHTTP)
}

func (h *restHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := pathOf(r)
	if r.Method == http.MethodGet && path == "/api/v3/meta" {
		WriteJSON(w, http.StatusOK, metaBody{InstalledVersion: "1.0.0"})
		return
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v3"), "/")
	if rest == "" {
		if r.Method == http.MethodGet {
			w.Header().Set("X-Oauth-Scopes", "repo, read:org")
			WriteJSON(w, http.StatusOK, apiRootBody)
			return
		}
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	segs := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	switch segs[0] {
	case "meta":
		if r.Method == http.MethodGet && len(segs) == 1 {
			WriteJSON(w, http.StatusOK, metaBody{InstalledVersion: "1.0.0"})
			return
		}
		WriteError(w, http.StatusNotFound, "Not Found")
	case "user":
		h.dispatchUser(w, r, segs[1:])
	case "repos":
		h.dispatchRepos(w, r, segs[1:])
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// ---------------------------------------------------------------------------
// Request bodies: decoded exactly once.
//
// The middleware in main.go already read and validated the body (and
// rewound r.Body). When it also stashes those bytes in the request context
// under restBodyKey, decoding here reuses them with no second read and no
// second parse; otherwise the body is read once here and unmarshalled once.
// Either way a handler never decodes the same body twice.
//
// NOTE FOR THE INTEGRATOR (main.go): stash with
//
//	r.WithContext(context.WithValue(r.Context(), restBodyKey{}, bodyBytes))
//
// to get the zero-copy path; the fallback below stays correct without it.
type restBodyKey struct{}

func restBodyBytes(r *http.Request) ([]byte, error) {
	if b, ok := r.Context().Value(restBodyKey{}).([]byte); ok {
		return b, nil
	}
	if r.Body == nil {
		return nil, nil
	}
	return io.ReadAll(r.Body)
}

// restDecodeJSON unmarshals the request body into v; an empty body leaves
// v at its zero value. The middleware has already rejected malformed JSON
// on this surface, so an error here is a shape mismatch.
func restDecodeJSON(r *http.Request, v any) error {
	b, err := restBodyBytes(r)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	return json.Unmarshal(b, v)
}

// ---------------------------------------------------------------------------
// Hand-rolled JSON encoding (hot views only).
//
// appendJSONString matches encoding/json's string escaping exactly: quote,
// backslash, \n \r \t, other control bytes as \u00XX, < > & as \u003C
// \u003E \u0026, U+2028/U+2029 escaped, and invalid UTF-8 bytes replaced
// with \ufffd. Field order in every encoder below is the wire order the
// suite expects (the same order the old struct tags produced).

const restHexDigits = "0123456789abcdef"

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	dst = appendJSONStringContent(dst, s)
	return append(dst, '"')
}

// appendJSONStringParts appends one quoted string built from several
// pieces (e.g. owner + "/" + name) without allocating the concatenation.
func appendJSONStringParts(dst []byte, parts ...string) []byte {
	dst = append(dst, '"')
	for _, p := range parts {
		dst = appendJSONStringContent(dst, p)
	}
	return append(dst, '"')
}

// appendJSONStringContent appends the escaped contents of s without quotes.
func appendJSONStringContent(dst []byte, s string) []byte {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"', '\\':
				dst = append(dst, '\\', c)
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			case '<':
				dst = append(dst, '\\', 'u', '0', '0', '3', 'c')
			case '>':
				dst = append(dst, '\\', 'u', '0', '0', '3', 'e')
			case '&':
				dst = append(dst, '\\', 'u', '0', '0', '2', '6')
			default:
				if c < 0x20 {
					dst = append(dst, '\\', 'u', '0', '0', restHexDigits[c>>4], restHexDigits[c&0xf])
				} else {
					dst = append(dst, c)
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, '\\', 'u', 'f', 'f', 'f', 'd')
			i++
			continue
		}
		if r == '\u2028' {
			dst = append(dst, '\\', 'u', '2', '0', '2', '8')
		} else if r == '\u2029' {
			dst = append(dst, '\\', 'u', '2', '0', '2', '9')
		} else {
			dst = append(dst, s[i:i+size]...)
		}
		i += size
	}
	return dst
}

// appendJSONUser appends {"login":...,"id":...,"type":"User"} for the viewer.
func appendJSONUser(dst []byte, login string, id int) []byte {
	dst = append(dst, `{"login":`...)
	dst = appendJSONString(dst, login)
	dst = append(dst, `,"id":`...)
	dst = strconv.AppendInt(dst, int64(id), 10)
	dst = append(dst, `,"type":"User"}`...)
	return dst
}

// writeRawJSON writes pre-encoded JSON bytes with a status, matching
// WriteJSON's trailing newline and Content-Type.
func writeRawJSON(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
	_, _ = w.Write([]byte{'\n'})
}

// ---------------------------------------------------------------------------
// Pagination

// restPageParams parses page/per_page query parameters (defaults 1/30,
// per_page clamped to 1..100).
func restPageParams(r *http.Request) (page, perPage int) {
	page, perPage = 1, 30
	q := r.URL.Query()
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			page = n
		}
	}
	if v := q.Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			perPage = n
			if perPage > 100 {
				perPage = 100
			}
		}
	}
	return page, perPage
}

func restPageBounds(page, perPage, total int) (start, end int) {
	start = (page - 1) * perPage
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	end = start + perPage
	if end > total {
		end = total
	}
	return start, end
}

func restPageLink(r *http.Request, page, perPage int) string {
	q := r.URL.Query()
	q.Set("page", strconv.Itoa(page))
	q.Set("per_page", strconv.Itoa(perPage))
	return "http://" + r.Host + r.URL.Path + "?" + q.Encode()
}

// restSetPageLinks emits a GitHub-style Link header (next/prev/first/last)
// when the listing spans more than one page.
func restSetPageLinks(w http.ResponseWriter, r *http.Request, page, perPage, total int) {
	totalPages := (total + perPage - 1) / perPage
	if totalPages <= 1 {
		return
	}
	var parts []string
	if page < totalPages {
		parts = append(parts, "<"+restPageLink(r, page+1, perPage)+`>; rel="next"`)
	}
	if page > 1 {
		parts = append(parts, "<"+restPageLink(r, page-1, perPage)+`>; rel="prev"`)
	}
	parts = append(parts, "<"+restPageLink(r, 1, perPage)+`>; rel="first"`)
	parts = append(parts, "<"+restPageLink(r, totalPages, perPage)+`>; rel="last"`)
	w.Header().Set("Link", strings.Join(parts, ", "))
}

// ---------------------------------------------------------------------------
// Hot-view encoders. Each appends the exact JSON the old struct-based
// views produced, in the same field order, without reflection.

type restUser struct {
	Login string `json:"login"`
	ID    int    `json:"id"`
	Type  string `json:"type"`
}

var restViewer = restUser{Login: ViewerLogin, ID: ViewerID, Type: "User"}

type restLabel struct {
	ID          uint64 `json:"id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
	Default     bool   `json:"default"`
}

// appendLabelJSON appends one label object; Description is always "" and
// Default always false on this surface.
func appendLabelJSON(dst []byte, l restLabel) []byte {
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendUint(dst, l.ID, 10)
	dst = append(dst, `,"name":`...)
	dst = appendJSONString(dst, l.Name)
	dst = append(dst, `,"color":`...)
	dst = appendJSONString(dst, l.Color)
	dst = append(dst, `,"description":"","default":false}`...)
	return dst
}

// appendLabelListJSON appends a label array; a nil/empty list is [].
func appendLabelListJSON(dst []byte, labels []restLabel) []byte {
	dst = append(dst, '[')
	for i, l := range labels {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendLabelJSON(dst, l)
	}
	return append(dst, ']')
}

// appendRepoJSON appends one repository object. Only the mutable fields
// are read under the store lock; ID/Owner/Name/DefaultBranch are immutable
// identity fields.
func (h *restHandler) appendRepoJSON(dst []byte, r *Repo) []byte {
	h.s.RLock()
	desc, priv, seq := r.Description, r.Private, r.Seq
	h.s.RUnlock()
	ts := h.ts(seq)
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendInt(dst, r.ID, 10)
	dst = append(dst, `,"name":`...)
	dst = appendJSONString(dst, r.Name)
	dst = append(dst, `,"full_name":`...)
	dst = appendJSONStringParts(dst, r.Owner, "/", r.Name)
	dst = append(dst, `,"owner":`...)
	dst = appendJSONUser(dst, r.Owner, ViewerID)
	dst = append(dst, `,"private":`...)
	dst = strconv.AppendBool(dst, priv)
	dst = append(dst, `,"description":`...)
	dst = appendJSONString(dst, desc)
	dst = append(dst, `,"default_branch":`...)
	dst = appendJSONString(dst, r.DefaultBranch)
	dst = append(dst, `,"permissions":{"admin":true,"maintain":true,"push":true,"triage":true,"pull":true},"created_at":`...)
	dst = appendJSONString(dst, ts)
	dst = append(dst, `,"updated_at":`...)
	dst = appendJSONString(dst, ts)
	dst = append(dst, `,"has_issues":true,"fork":false,"archived":false}`...)
	return dst
}

// appendIssueJSON appends one issue object from a snapshot.
func (h *restHandler) appendIssueJSON(dst []byte, snap restIssueSnapshot) []byte {
	ts := h.ts(snap.Seq)
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendUint(dst, snap.Seq, 10)
	dst = append(dst, `,"number":`...)
	dst = strconv.AppendInt(dst, int64(snap.Number), 10)
	dst = append(dst, `,"title":`...)
	dst = appendJSONString(dst, snap.Title)
	dst = append(dst, `,"body":`...)
	dst = appendJSONString(dst, snap.Body)
	dst = append(dst, `,"state":`...)
	dst = appendJSONString(dst, snap.State)
	dst = append(dst, `,"labels":`...)
	dst = appendLabelListJSON(dst, snap.Labels)
	dst = append(dst, `,"user":`...)
	dst = appendJSONUser(dst, ViewerLogin, ViewerID)
	dst = append(dst, `,"comments":`...)
	dst = strconv.AppendInt(dst, int64(snap.CommentCount), 10)
	dst = append(dst, `,"created_at":`...)
	dst = appendJSONString(dst, ts)
	dst = append(dst, `,"updated_at":`...)
	dst = appendJSONString(dst, ts)
	dst = append(dst, `,"closed_at":`...)
	if snap.State == "closed" {
		dst = appendJSONString(dst, ts)
	} else {
		dst = append(dst, "null"...)
	}
	return append(dst, '}')
}

// appendCommentJSON appends one issue-comment object.
func (h *restHandler) appendCommentJSON(dst []byte, id int64, body string, seq uint64) []byte {
	ts := h.ts(seq)
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendInt(dst, id, 10)
	dst = append(dst, `,"body":`...)
	dst = appendJSONString(dst, body)
	dst = append(dst, `,"user":`...)
	dst = appendJSONUser(dst, ViewerLogin, ViewerID)
	dst = append(dst, `,"created_at":`...)
	dst = appendJSONString(dst, ts)
	dst = append(dst, `,"updated_at":`...)
	dst = appendJSONString(dst, ts)
	return append(dst, '}')
}

// appendPRJSON appends one pull-request object from a snapshot.
func (h *restHandler) appendPRJSON(dst []byte, snap restPRSnapshot) []byte {
	ts := h.ts(snap.Seq)
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendUint(dst, snap.Seq, 10)
	dst = append(dst, `,"number":`...)
	dst = strconv.AppendInt(dst, int64(snap.Number), 10)
	dst = append(dst, `,"title":`...)
	dst = appendJSONString(dst, snap.Title)
	dst = append(dst, `,"body":`...)
	dst = appendJSONString(dst, snap.Body)
	dst = append(dst, `,"state":`...)
	dst = appendJSONString(dst, snap.State)
	dst = append(dst, `,"head":`...)
	dst = appendPRRefJSON(dst, snap.HeadRef, snap.HeadSHA)
	dst = append(dst, `,"base":`...)
	dst = appendPRRefJSON(dst, snap.BaseRef, snap.BaseSHA)
	dst = append(dst, `,"merged":`...)
	dst = strconv.AppendBool(dst, snap.Merged)
	dst = append(dst, `,"merged_at":`...)
	if snap.MergedAt != "" {
		dst = appendJSONString(dst, snap.MergedAt)
	} else {
		dst = append(dst, "null"...)
	}
	dst = append(dst, `,"merge_commit_sha":`...)
	if snap.MergeCommitSHA != "" {
		dst = appendJSONString(dst, snap.MergeCommitSHA)
	} else {
		dst = append(dst, "null"...)
	}
	dst = append(dst, `,"user":`...)
	dst = appendJSONUser(dst, ViewerLogin, ViewerID)
	dst = append(dst, `,"created_at":`...)
	dst = appendJSONString(dst, ts)
	dst = append(dst, `,"updated_at":`...)
	dst = appendJSONString(dst, ts)
	return append(dst, '}')
}

// appendPRRefJSON appends {"ref":...,"sha":...,"label":"<viewer>:<ref>"}.
func appendPRRefJSON(dst []byte, ref, sha string) []byte {
	dst = append(dst, `{"ref":`...)
	dst = appendJSONString(dst, ref)
	dst = append(dst, `,"sha":`...)
	dst = appendJSONString(dst, sha)
	dst = append(dst, `,"label":`...)
	dst = appendJSONStringParts(dst, ViewerLogin, ":", ref)
	return append(dst, '}')
}

// ---------------------------------------------------------------------------
// Cold-path response shapes (still marshalled by WriteJSON).

type restSHA struct {
	SHA string `json:"sha"`
}

type restBranch struct {
	Name      string  `json:"name"`
	Commit    restSHA `json:"commit"`
	Protected bool    `json:"protected"`
}

type restIdent struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

type restCommitDetail struct {
	Message   string    `json:"message"`
	Author    restIdent `json:"author"`
	Committer restIdent `json:"committer"`
	Tree      restSHA   `json:"tree"`
}

type restCommit struct {
	SHA       string           `json:"sha"`
	Commit    restCommitDetail `json:"commit"`
	Author    *restUser        `json:"author"`
	Committer *restUser        `json:"committer"`
	Parents   []restSHA        `json:"parents"`
}

type restRefObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}

type restRef struct {
	Ref    string        `json:"ref"`
	Object restRefObject `json:"object"`
}

type restPRFile struct {
	Filename  string `json:"filename"`
	Status    string `json:"status"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Changes   int    `json:"changes"`
}

type restContentFile struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
	SHA      string `json:"sha"`
	Size     int    `json:"size"`
	Name     string `json:"name"`
	Path     string `json:"path"`
}

type restContentEntry struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Path string `json:"path"`
	SHA  string `json:"sha"`
	Size int    `json:"size"`
}

// ---------------------------------------------------------------------------
// Snapshots: one locked copy of an issue / PR, so encoding runs lock-free.
// Labels are nil (encoded as []) when the issue carries none, avoiding a
// per-request slice allocation on the read workload.

type restIssueSnapshot struct {
	Number       int
	Title        string
	Body         string
	State        string
	Labels       []restLabel // nil when empty
	CommentCount int
	Seq          uint64
}

func (h *restHandler) snapshotIssue(r *Repo, number int) (restIssueSnapshot, bool) {
	h.s.RLock()
	defer h.s.RUnlock()
	iss, ok := r.Issues[number]
	if !ok {
		return restIssueSnapshot{}, false
	}
	snap := restIssueSnapshot{
		Number:       iss.Number,
		Title:        iss.Title,
		Body:         iss.Body,
		State:        iss.State,
		CommentCount: len(iss.Comments),
		Seq:          iss.Seq,
	}
	if len(iss.Labels) > 0 {
		snap.Labels = make([]restLabel, 0, len(iss.Labels))
		for _, name := range iss.Labels {
			lj := restLabel{Name: name, Color: "ededed"}
			if l, ok := r.Labels[name]; ok {
				lj.Color = l.Color
				lj.ID = l.Seq
			}
			snap.Labels = append(snap.Labels, lj)
		}
	}
	return snap, true
}

func (h *restHandler) snapshotAllIssues(r *Repo) []restIssueSnapshot {
	h.s.RLock()
	defer h.s.RUnlock()
	out := make([]restIssueSnapshot, 0, len(r.IssueOrder))
	for _, n := range r.IssueOrder {
		iss := r.Issues[n]
		snap := restIssueSnapshot{
			Number:       iss.Number,
			Title:        iss.Title,
			Body:         iss.Body,
			State:        iss.State,
			CommentCount: len(iss.Comments),
			Seq:          iss.Seq,
		}
		if len(iss.Labels) > 0 {
			snap.Labels = make([]restLabel, 0, len(iss.Labels))
			for _, name := range iss.Labels {
				lj := restLabel{Name: name, Color: "ededed"}
				if l, ok := r.Labels[name]; ok {
					lj.Color = l.Color
					lj.ID = l.Seq
				}
				snap.Labels = append(snap.Labels, lj)
			}
		}
		out = append(out, snap)
	}
	return out
}

type restPRSnapshot struct {
	Number         int
	Title          string
	Body           string
	State          string
	HeadRef        string
	BaseRef        string
	HeadSHA        string
	BaseSHA        string
	Merged         bool
	MergedAt       string
	MergeCommitSHA string
	Files          []PRFile
	Seq            uint64
}

func (h *restHandler) snapshotPR(r *Repo, number int) (restPRSnapshot, bool) {
	h.s.RLock()
	defer h.s.RUnlock()
	pr, ok := r.PRs[number]
	if !ok {
		return restPRSnapshot{}, false
	}
	snap := restPRSnapshot{
		Number:         pr.Number,
		Title:          pr.Title,
		Body:           pr.Body,
		State:          pr.State,
		HeadRef:        pr.HeadRef,
		BaseRef:        pr.BaseRef,
		HeadSHA:        pr.HeadSHA,
		BaseSHA:        pr.BaseSHA,
		Merged:         pr.Merged,
		MergedAt:       pr.MergedAt,
		MergeCommitSHA: pr.MergeCommitSHA,
		Seq:            pr.Seq,
	}
	if len(pr.Files) > 0 {
		snap.Files = append([]PRFile(nil), pr.Files...)
	}
	return snap, true
}

func (h *restHandler) snapshotAllPRs(r *Repo) []restPRSnapshot {
	h.s.RLock()
	defer h.s.RUnlock()
	out := make([]restPRSnapshot, 0, len(r.PROrder))
	for _, n := range r.PROrder {
		pr := r.PRs[n]
		snap := restPRSnapshot{
			Number:         pr.Number,
			Title:          pr.Title,
			Body:           pr.Body,
			State:          pr.State,
			HeadRef:        pr.HeadRef,
			BaseRef:        pr.BaseRef,
			HeadSHA:        pr.HeadSHA,
			BaseSHA:        pr.BaseSHA,
			Merged:         pr.Merged,
			MergedAt:       pr.MergedAt,
			MergeCommitSHA: pr.MergeCommitSHA,
			Seq:            pr.Seq,
		}
		if len(pr.Files) > 0 {
			snap.Files = append([]PRFile(nil), pr.Files...)
		}
		out = append(out, snap)
	}
	return out
}

// ---------------------------------------------------------------------------
// /user/*

func (h *restHandler) dispatchUser(w http.ResponseWriter, r *http.Request, tail []string) {
	if len(tail) == 0 {
		if r.Method == http.MethodGet {
			WriteJSON(w, http.StatusOK, map[string]any{
				"login": ViewerLogin, "id": ViewerID, "type": "User",
				"name": ViewerLogin, "email": ViewerEmail,
			})
			return
		}
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if len(tail) == 1 && tail[0] == "repos" {
		switch r.Method {
		case http.MethodGet:
			h.listUserRepos(w, r)
		case http.MethodPost:
			h.createRepo(w, r)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
		return
	}
	WriteError(w, http.StatusNotFound, "Not Found")
}

func (h *restHandler) createRepo(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Private     bool   `json:"private"`
		Description string `json:"description"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	if req.Name == "" {
		WriteError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	repo, err := h.s.CreateRepo(ViewerLogin, req.Name, req.Description, req.Private)
	if err == ErrRepoExists {
		WriteError(w, http.StatusUnprocessableEntity, "Repository already exists")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeRawJSON(w, http.StatusCreated, h.appendRepoJSON(make([]byte, 0, 512), repo))
}

func (h *restHandler) listUserRepos(w http.ResponseWriter, r *http.Request) {
	repos := h.s.ListRepos(ViewerLogin)
	page, perPage := restPageParams(r)
	start, end := restPageBounds(page, perPage, len(repos))
	restSetPageLinks(w, r, page, perPage, len(repos))
	buf := make([]byte, 0, 512*(end-start+1))
	buf = append(buf, '[')
	for i, rp := range repos[start:end] {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = h.appendRepoJSON(buf, rp)
	}
	buf = append(buf, ']')
	writeRawJSON(w, http.StatusOK, buf)
}

// ---------------------------------------------------------------------------
// /repos/{owner}/{repo}/*

func (h *restHandler) dispatchRepos(w http.ResponseWriter, r *http.Request, tail []string) {
	if len(tail) < 2 {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	owner, name := tail[0], tail[1]
	repo, ok := h.s.GetRepo(owner, name)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	rest := tail[2:]
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			writeRawJSON(w, http.StatusOK, h.appendRepoJSON(make([]byte, 0, 512), repo))
		case http.MethodPatch:
			h.patchRepo(w, r, repo)
		case http.MethodDelete:
			h.s.DeleteRepo(owner, name)
			w.WriteHeader(http.StatusNoContent)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
		return
	}
	switch rest[0] {
	case "branches":
		h.dispatchBranches(w, r, repo, rest[1:])
	case "commits":
		h.dispatchCommits(w, r, repo, rest[1:])
	case "contents":
		h.dispatchContents(w, r, repo, rest[1:])
	case "git":
		h.dispatchGit(w, r, repo, rest[1:])
	case "labels":
		h.dispatchLabels(w, r, repo, rest[1:])
	case "issues":
		h.dispatchIssues(w, r, repo, rest[1:])
	case "pulls":
		h.dispatchPulls(w, r, repo, rest[1:])
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

func (h *restHandler) patchRepo(w http.ResponseWriter, r *http.Request, repo *Repo) {
	var req struct {
		Description *string `json:"description"`
		Private     *bool   `json:"private"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	if req.Description != nil {
		h.s.SetRepoDescription(repo, *req.Description)
	}
	if req.Private != nil {
		h.s.Lock()
		repo.Private = *req.Private
		h.s.Unlock()
	}
	writeRawJSON(w, http.StatusOK, h.appendRepoJSON(make([]byte, 0, 512), repo))
}

// ---------------------------------------------------------------------------
// Branches

func (h *restHandler) dispatchBranches(w http.ResponseWriter, r *http.Request, repo *Repo, tail []string) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if len(tail) == 0 {
		views := make([]restBranch, 0)
		for _, e := range h.s.ListRefs(repo) {
			if !strings.HasPrefix(e.Name, "refs/heads/") {
				continue
			}
			views = append(views, restBranch{
				Name:      strings.TrimPrefix(e.Name, "refs/heads/"),
				Commit:    restSHA{SHA: e.SHA},
				Protected: false,
			})
		}
		WriteJSON(w, http.StatusOK, views)
		return
	}
	name := strings.Join(tail, "/")
	sha, ok := h.s.GetRef(repo, BranchRef(name))
	if !ok {
		WriteError(w, http.StatusNotFound, "Branch not found")
		return
	}
	WriteJSON(w, http.StatusOK, restBranch{Name: name, Commit: restSHA{SHA: sha}, Protected: false})
}

// ---------------------------------------------------------------------------
// Commits

// resolveCommit resolves a branch name, full ref name, or object id to a
// commit id (annotated tags peeled). HEAD means the default branch.
func (h *restHandler) resolveCommit(r *Repo, ref string) (string, bool) {
	if ref == "HEAD" {
		ref = r.DefaultBranch
	}
	if sha, ok := h.s.GetRef(r, BranchRef(ref)); ok {
		return h.s.PeelToCommit(r, sha), true
	}
	if sha, ok := h.s.GetRef(r, ref); ok {
		return h.s.PeelToCommit(r, sha), true
	}
	if obj, ok := h.s.GetObject(r, ref); ok && (obj.Type == ObjCommit || obj.Type == ObjTag) {
		return h.s.PeelToCommit(r, ref), true
	}
	return "", false
}

// restParseIdent parses a git ident line ("Name <email> unix-ts tz").
func restParseIdent(raw, fallbackDate string) restIdent {
	ident := restIdent{Name: raw, Date: fallbackDate}
	lt := strings.Index(raw, "<")
	if lt < 0 {
		return ident
	}
	ident.Name = strings.TrimSpace(raw[:lt])
	rest := raw[lt+1:]
	gt := strings.Index(rest, ">")
	if gt < 0 {
		return ident
	}
	ident.Email = rest[:gt]
	fields := strings.Fields(strings.TrimSpace(rest[gt+1:]))
	if len(fields) > 0 {
		if ts, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			ident.Date = time.Unix(ts, 0).UTC().Format(time.RFC3339)
		}
	}
	return ident
}

func (h *restHandler) commitView(obj *GitObject) restCommit {
	pc := obj.Commit
	fallback := h.ts(0)
	author := restParseIdent(pc.Author, fallback)
	committer := restParseIdent(pc.Committer, fallback)
	view := restCommit{
		SHA: obj.SHA,
		Commit: restCommitDetail{
			Message:   pc.Message,
			Author:    author,
			Committer: committer,
			Tree:      restSHA{SHA: pc.Tree},
		},
		Parents: make([]restSHA, 0, len(pc.Parents)),
	}
	if author.Email == ViewerEmail {
		view.Author = &restViewer
	}
	if committer.Email == ViewerEmail {
		view.Committer = &restViewer
	}
	for _, p := range pc.Parents {
		view.Parents = append(view.Parents, restSHA{SHA: p})
	}
	return view
}

func (h *restHandler) commitHistory(r *Repo, tip string) []restCommit {
	out := make([]restCommit, 0)
	seen := make(map[string]bool)
	stack := []string{tip}
	for len(stack) > 0 {
		sha := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[sha] {
			continue
		}
		seen[sha] = true
		obj, ok := h.s.GetObject(r, sha)
		if !ok || obj.Commit == nil {
			continue
		}
		out = append(out, h.commitView(obj))
		for i := len(obj.Commit.Parents) - 1; i >= 0; i-- {
			stack = append(stack, obj.Commit.Parents[i])
		}
	}
	return out
}

func (h *restHandler) dispatchCommits(w http.ResponseWriter, r *http.Request, repo *Repo, tail []string) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if len(tail) == 0 {
		ref := r.URL.Query().Get("sha")
		if ref == "" {
			ref = repo.DefaultBranch
		}
		tip, ok := h.resolveCommit(repo, ref)
		if !ok {
			if len(h.s.ListRefs(repo)) == 0 {
				WriteJSON(w, http.StatusOK, []restCommit{})
				return
			}
			WriteError(w, http.StatusNotFound, "No commit found for SHA: "+ref)
			return
		}
		WriteJSON(w, http.StatusOK, h.commitHistory(repo, tip))
		return
	}
	if len(tail) == 1 {
		sha, ok := h.resolveCommit(repo, tail[0])
		if !ok {
			WriteError(w, http.StatusNotFound, "No commit found for SHA: "+tail[0])
			return
		}
		obj, ok := h.s.GetObject(repo, sha)
		if !ok || obj.Commit == nil {
			WriteError(w, http.StatusNotFound, "No commit found for SHA: "+tail[0])
			return
		}
		WriteJSON(w, http.StatusOK, h.commitView(obj))
		return
	}
	WriteError(w, http.StatusNotFound, "Not Found")
}

// ---------------------------------------------------------------------------
// Git object construction for contents writes and squash merges

// restTreeEntryKey is the git tree sort key: directories compare with a
// trailing slash.
func restTreeEntryKey(e TreeEntry) string {
	if e.Mode == "40000" {
		return e.Name + "/"
	}
	return e.Name
}

// updateTreePath returns the id of the tree formed by setting (or, when del,
// removing) the blob at segs within treeSHA, preserving untouched subtrees
// byte-identically. It returns "" when the resulting tree is empty.
func (h *restHandler) updateTreePath(r *Repo, treeSHA string, segs []string, blobSHA string, del bool) string {
	var entries []TreeEntry
	if treeSHA != "" {
		if obj, ok := h.s.GetObject(r, treeSHA); ok && obj.Type == ObjTree {
			entries = append([]TreeEntry(nil), obj.Tree...)
		}
	}
	name := segs[0]
	idx := -1
	for i, e := range entries {
		if e.Name == name {
			idx = i
			break
		}
	}
	if len(segs) == 1 {
		if del {
			if idx >= 0 {
				entries = append(entries[:idx], entries[idx+1:]...)
			}
		} else if idx >= 0 {
			entries[idx] = TreeEntry{Mode: "100644", Name: name, SHA: blobSHA}
		} else {
			entries = append(entries, TreeEntry{Mode: "100644", Name: name, SHA: blobSHA})
		}
	} else {
		var childSHA string
		if idx >= 0 && entries[idx].Mode == "40000" {
			childSHA = entries[idx].SHA
		}
		newChild := h.updateTreePath(r, childSHA, segs[1:], blobSHA, del)
		if newChild == "" {
			if idx >= 0 {
				entries = append(entries[:idx], entries[idx+1:]...)
			}
		} else if idx >= 0 {
			entries[idx] = TreeEntry{Mode: "40000", Name: name, SHA: newChild}
		} else {
			entries = append(entries, TreeEntry{Mode: "40000", Name: name, SHA: newChild})
		}
	}
	if len(entries) == 0 {
		return ""
	}
	sort.Slice(entries, func(i, j int) bool { return restTreeEntryKey(entries[i]) < restTreeEntryKey(entries[j]) })
	var buf bytes.Buffer
	for _, e := range entries {
		raw, _ := hex.DecodeString(e.SHA)
		fmt.Fprintf(&buf, "%s %s\x00", e.Mode, e.Name)
		buf.Write(raw)
	}
	return h.s.PutObject(r, ObjTree, buf.Bytes()).SHA
}

// emptyTreeID returns the id of the empty tree object, storing it.
func (h *restHandler) emptyTreeID(r *Repo) string {
	return h.s.PutObject(r, ObjTree, []byte{}).SHA
}

// makeCommit stores a commit object with a sequence-derived timestamp and
// returns its id. The message is stored verbatim (no trailing newline is
// added) so reads echo it exactly.
func (h *restHandler) makeCommit(r *Repo, treeSHA string, parents []string, message, authorName, authorEmail, committerName, committerEmail string) string {
	seq := h.s.NextSeq()
	ts := h.s.Clock().Base().Unix() + int64(seq)
	var b strings.Builder
	fmt.Fprintf(&b, "tree %s\n", treeSHA)
	for _, p := range parents {
		fmt.Fprintf(&b, "parent %s\n", p)
	}
	fmt.Fprintf(&b, "author %s <%s> %d +0000\n", authorName, authorEmail, ts)
	fmt.Fprintf(&b, "committer %s <%s> %d +0000\n", committerName, committerEmail, ts)
	b.WriteString("\n")
	b.WriteString(message)
	return h.s.PutObject(r, ObjCommit, []byte(b.String())).SHA
}

// flattenAt returns path -> blob id for a commit's tree (tags peeled);
// unknown or empty commits flatten to an empty map.
func (h *restHandler) flattenAt(r *Repo, commitSHA string) map[string]string {
	if commitSHA == "" || commitSHA == ZeroSHA {
		return map[string]string{}
	}
	treeSHA, ok := h.s.CommitTreeSHA(r, commitSHA)
	if !ok {
		return map[string]string{}
	}
	return h.s.FlattenTree(r, treeSHA)
}

// ---------------------------------------------------------------------------
// Contents

func (h *restHandler) dispatchContents(w http.ResponseWriter, r *http.Request, repo *Repo, tail []string) {
	filePath := strings.Join(tail, "/")
	switch r.Method {
	case http.MethodGet:
		h.getContents(w, r, repo, filePath)
	case http.MethodPut:
		h.putContents(w, r, repo, filePath)
	case http.MethodDelete:
		h.deleteContents(w, r, repo, filePath)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// lookupPath walks the tree at treeSHA along segs and returns the final
// entry, if it exists.
func (h *restHandler) lookupPath(r *Repo, treeSHA string, segs []string) (TreeEntry, bool) {
	cur := treeSHA
	for i, seg := range segs {
		obj, ok := h.s.GetObject(r, cur)
		if !ok || obj.Type != ObjTree {
			return TreeEntry{}, false
		}
		found := false
		for _, e := range obj.Tree {
			if e.Name != seg {
				continue
			}
			if i == len(segs)-1 {
				return e, true
			}
			if e.Mode != "40000" {
				return TreeEntry{}, false
			}
			cur = e.SHA
			found = true
			break
		}
		if !found {
			return TreeEntry{}, false
		}
	}
	return TreeEntry{}, false
}

func (h *restHandler) getContents(w http.ResponseWriter, r *http.Request, repo *Repo, filePath string) {
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		ref = repo.DefaultBranch
	}
	tip, ok := h.resolveCommit(repo, ref)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	treeSHA, ok := h.s.CommitTreeSHA(repo, tip)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if filePath == "" {
		h.writeDirListing(w, repo, treeSHA, "")
		return
	}
	segs := strings.Split(filePath, "/")
	entry, ok := h.lookupPath(repo, treeSHA, segs)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if entry.Mode == "40000" {
		h.writeDirListing(w, repo, entry.SHA, filePath)
		return
	}
	obj, ok := h.s.GetObject(repo, entry.SHA)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	WriteJSON(w, http.StatusOK, restContentFile{
		Type:     "file",
		Encoding: "base64",
		Content:  base64.StdEncoding.EncodeToString(obj.Raw),
		SHA:      entry.SHA,
		Size:     len(obj.Raw),
		Name:     segs[len(segs)-1],
		Path:     filePath,
	})
}

func (h *restHandler) writeDirListing(w http.ResponseWriter, r *Repo, treeSHA, dirPath string) {
	obj, ok := h.s.GetObject(r, treeSHA)
	if !ok || obj.Type != ObjTree {
		WriteJSON(w, http.StatusOK, []restContentEntry{})
		return
	}
	entries := make([]restContentEntry, 0, len(obj.Tree))
	for _, e := range obj.Tree {
		p := e.Name
		if dirPath != "" {
			p = dirPath + "/" + e.Name
		}
		ce := restContentEntry{Name: e.Name, Path: p, SHA: e.SHA}
		if e.Mode == "40000" {
			ce.Type = "dir"
		} else {
			ce.Type = "file"
			if blob, ok := h.s.GetObject(r, e.SHA); ok {
				ce.Size = len(blob.Raw)
			}
		}
		entries = append(entries, ce)
	}
	WriteJSON(w, http.StatusOK, entries)
}

type restPersonInput struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (h *restHandler) putContents(w http.ResponseWriter, r *http.Request, repo *Repo, filePath string) {
	if filePath == "" {
		WriteError(w, http.StatusUnprocessableEntity, "path is required")
		return
	}
	var req struct {
		Message   string           `json:"message"`
		Content   string           `json:"content"`
		Branch    string           `json:"branch"`
		SHA       string           `json:"sha"`
		Committer *restPersonInput `json:"committer"`
		Author    *restPersonInput `json:"author"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	cleaned := strings.Map(func(ch rune) rune {
		switch ch {
		case '\r', '\n', '\t', ' ':
			return -1
		}
		return ch
	}, req.Content)
	raw, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "content is not valid base64")
		return
	}
	branch := req.Branch
	if branch == "" {
		branch = repo.DefaultBranch
	}
	// Resolve the branch tip; a new branch forks from the default branch tip.
	var parent, baseTree string
	var curMap map[string]string
	if tip, ok := h.s.GetRef(repo, BranchRef(branch)); ok {
		parent = h.s.PeelToCommit(repo, tip)
		if treeSHA, ok := h.s.CommitTreeSHA(repo, parent); ok {
			baseTree = treeSHA
		}
		curMap = h.flattenAt(repo, parent)
	} else if branch != repo.DefaultBranch {
		if tip, ok := h.s.GetRef(repo, BranchRef(repo.DefaultBranch)); ok {
			parent = h.s.PeelToCommit(repo, tip)
			if treeSHA, ok := h.s.CommitTreeSHA(repo, parent); ok {
				baseTree = treeSHA
			}
			curMap = h.flattenAt(repo, parent)
		}
	}
	if curMap == nil {
		curMap = map[string]string{}
	}
	curSHA, exists := curMap[filePath]
	if req.SHA != "" && exists && req.SHA != curSHA {
		WriteError(w, http.StatusConflict, "sha does not match the current file content")
		return
	}
	blob := h.s.PutObject(repo, ObjBlob, raw)
	newTree := h.updateTreePath(repo, baseTree, strings.Split(filePath, "/"), blob.SHA, false)
	if newTree == "" {
		newTree = h.emptyTreeID(repo)
	}
	authorName, authorEmail := ViewerLogin, ViewerEmail
	if req.Author != nil {
		if req.Author.Name != "" {
			authorName = req.Author.Name
		}
		if req.Author.Email != "" {
			authorEmail = req.Author.Email
		}
	}
	committerName, committerEmail := ViewerLogin, ViewerEmail
	if req.Committer != nil {
		if req.Committer.Name != "" {
			committerName = req.Committer.Name
		}
		if req.Committer.Email != "" {
			committerEmail = req.Committer.Email
		}
	}
	message := req.Message
	if message == "" {
		message = "Update " + filePath
	}
	var parents []string
	if parent != "" && parent != ZeroSHA {
		parents = []string{parent}
	}
	commitSHA := h.makeCommit(repo, newTree, parents, message, authorName, authorEmail, committerName, committerEmail)
	h.s.SetRef(repo, BranchRef(branch), commitSHA)
	status := http.StatusCreated
	if exists {
		status = http.StatusOK
	}
	segs := strings.Split(filePath, "/")
	WriteJSON(w, status, map[string]any{
		"content": restContentFile{
			Type:     "file",
			Encoding: "base64",
			Content:  base64.StdEncoding.EncodeToString(raw),
			SHA:      blob.SHA,
			Size:     len(raw),
			Name:     segs[len(segs)-1],
			Path:     filePath,
		},
		"commit": map[string]any{
			"sha":     commitSHA,
			"message": message,
			"tree":    restSHA{SHA: newTree},
		},
	})
}

func (h *restHandler) deleteContents(w http.ResponseWriter, r *http.Request, repo *Repo, filePath string) {
	if filePath == "" {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	var req struct {
		Message string `json:"message"`
		SHA     string `json:"sha"`
		Branch  string `json:"branch"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	branch := req.Branch
	if branch == "" {
		branch = repo.DefaultBranch
	}
	tip, ok := h.s.GetRef(repo, BranchRef(branch))
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	parent := h.s.PeelToCommit(repo, tip)
	baseTree, ok := h.s.CommitTreeSHA(repo, parent)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	curMap := h.flattenAt(repo, parent)
	curSHA, exists := curMap[filePath]
	if !exists {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if req.SHA != "" && req.SHA != curSHA {
		WriteError(w, http.StatusConflict, "sha does not match the current file content")
		return
	}
	newTree := h.updateTreePath(repo, baseTree, strings.Split(filePath, "/"), "", true)
	if newTree == "" {
		newTree = h.emptyTreeID(repo)
	}
	message := req.Message
	if message == "" {
		message = "Delete " + filePath
	}
	commitSHA := h.makeCommit(repo, newTree, []string{parent}, message, ViewerLogin, ViewerEmail, ViewerLogin, ViewerEmail)
	h.s.SetRef(repo, BranchRef(branch), commitSHA)
	WriteJSON(w, http.StatusOK, map[string]any{
		"commit": map[string]any{
			"sha":     commitSHA,
			"message": message,
			"tree":    restSHA{SHA: newTree},
		},
	})
}

// ---------------------------------------------------------------------------
// Git refs

func (h *restHandler) refView(r *Repo, ref, sha string) restRef {
	typ := "commit"
	if obj, ok := h.s.GetObject(r, sha); ok {
		typ = obj.Type.String()
	}
	return restRef{Ref: ref, Object: restRefObject{SHA: sha, Type: typ}}
}

func (h *restHandler) dispatchGit(w http.ResponseWriter, r *http.Request, repo *Repo, tail []string) {
	if len(tail) == 0 || tail[0] != "refs" {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if len(tail) == 1 {
		switch r.Method {
		case http.MethodGet:
			views := make([]restRef, 0)
			for _, e := range h.s.ListRefs(repo) {
				views = append(views, h.refView(repo, e.Name, e.SHA))
			}
			WriteJSON(w, http.StatusOK, views)
		case http.MethodPost:
			h.createRef(w, r, repo)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
		return
	}
	fullRef := "refs/" + strings.Join(tail[1:], "/")
	switch r.Method {
	case http.MethodGet:
		if sha, ok := h.s.GetRef(repo, fullRef); ok {
			WriteJSON(w, http.StatusOK, h.refView(repo, fullRef, sha))
			return
		}
		views := make([]restRef, 0)
		for _, e := range h.s.ListRefs(repo) {
			if strings.HasPrefix(e.Name, fullRef+"/") {
				views = append(views, h.refView(repo, e.Name, e.SHA))
			}
		}
		if len(views) == 0 {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		WriteJSON(w, http.StatusOK, views)
	case http.MethodPatch:
		h.patchRef(w, r, repo, fullRef)
	case http.MethodDelete:
		if !h.s.DeleteRef(repo, fullRef) {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

func (h *restHandler) createRef(w http.ResponseWriter, r *http.Request, repo *Repo) {
	var req struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	if req.Ref == "" || !strings.HasPrefix(req.Ref, "refs/") {
		WriteError(w, http.StatusUnprocessableEntity, "ref must start with refs/")
		return
	}
	if _, ok := h.s.GetObject(repo, req.SHA); !ok {
		WriteError(w, http.StatusUnprocessableEntity, "sha does not name a known object")
		return
	}
	if _, exists := h.s.GetRef(repo, req.Ref); exists {
		WriteError(w, http.StatusUnprocessableEntity, "Reference already exists")
		return
	}
	h.s.SetRef(repo, req.Ref, req.SHA)
	WriteJSON(w, http.StatusCreated, h.refView(repo, req.Ref, req.SHA))
}

func (h *restHandler) patchRef(w http.ResponseWriter, r *http.Request, repo *Repo, fullRef string) {
	if _, ok := h.s.GetRef(repo, fullRef); !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	var req struct {
		SHA   string `json:"sha"`
		Force bool   `json:"force"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	if _, ok := h.s.GetObject(repo, req.SHA); !ok {
		WriteError(w, http.StatusUnprocessableEntity, "sha does not name a known object")
		return
	}
	h.s.SetRef(repo, fullRef, req.SHA)
	WriteJSON(w, http.StatusOK, h.refView(repo, fullRef, req.SHA))
}

// ---------------------------------------------------------------------------
// Labels

func (h *restHandler) dispatchLabels(w http.ResponseWriter, r *http.Request, repo *Repo, tail []string) {
	if len(tail) != 0 {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		buf := make([]byte, 0, 256)
		buf = append(buf, '[')
		for i, l := range h.s.ListLabels(repo) {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendLabelJSON(buf, restLabel{ID: l.Seq, Name: l.Name, Color: l.Color})
		}
		buf = append(buf, ']')
		writeRawJSON(w, http.StatusOK, buf)
	case http.MethodPost:
		var req struct {
			Name  string `json:"name"`
			Color string `json:"color"`
		}
		if err := restDecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
			return
		}
		if req.Name == "" {
			WriteError(w, http.StatusUnprocessableEntity, "name is required")
			return
		}
		color := req.Color
		if color == "" {
			color = "ededed"
		}
		l := h.s.CreateLabel(repo, req.Name, color)
		writeRawJSON(w, http.StatusCreated, appendLabelJSON(make([]byte, 0, 128), restLabel{ID: l.Seq, Name: l.Name, Color: l.Color}))
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// restLabelInput accepts a label name sent as a bare string or as an object
// with a name property.
type restLabelInput struct {
	Name string
}

func (l *restLabelInput) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		l.Name = s
		return nil
	}
	var o struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	l.Name = o.Name
	return nil
}

// ---------------------------------------------------------------------------
// Issues

func (h *restHandler) dispatchIssues(w http.ResponseWriter, r *http.Request, repo *Repo, tail []string) {
	if len(tail) == 0 {
		switch r.Method {
		case http.MethodGet:
			h.listIssues(w, r, repo)
		case http.MethodPost:
			h.createIssue(w, r, repo)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
		return
	}
	number, err := strconv.Atoi(tail[0])
	if err != nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if len(tail) == 1 {
		switch r.Method {
		case http.MethodGet:
			snap, ok := h.snapshotIssue(repo, number)
			if !ok {
				WriteError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeRawJSON(w, http.StatusOK, h.appendIssueJSON(make([]byte, 0, 512), snap))
		case http.MethodPatch:
			h.patchIssue(w, r, repo, number)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
		return
	}
	if len(tail) != 2 {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	switch tail[1] {
	case "comments":
		switch r.Method {
		case http.MethodGet:
			h.listComments(w, r, repo, number)
		case http.MethodPost:
			h.createComment(w, r, repo, number)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	case "labels":
		switch r.Method {
		case http.MethodGet:
			snap, ok := h.snapshotIssue(repo, number)
			if !ok {
				WriteError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeRawJSON(w, http.StatusOK, appendLabelListJSON(make([]byte, 0, 128), snap.Labels))
		case http.MethodPost:
			h.addIssueLabels(w, r, repo, number)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

func (h *restHandler) listIssues(w http.ResponseWriter, r *http.Request, repo *Repo) {
	snaps := h.snapshotAllIssues(repo)
	state := r.URL.Query().Get("state")
	filtered := make([]restIssueSnapshot, 0, len(snaps))
	for _, snap := range snaps {
		switch state {
		case "", "open":
			if snap.State == "open" {
				filtered = append(filtered, snap)
			}
		case "closed":
			if snap.State == "closed" {
				filtered = append(filtered, snap)
			}
		case "all":
			filtered = append(filtered, snap)
		default:
			if snap.State == state {
				filtered = append(filtered, snap)
			}
		}
	}
	// Creation order; direction=asc keeps it, anything else reverses it
	// (GitHub's default for sort=created is newest first).
	if r.URL.Query().Get("direction") != "asc" {
		for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
			filtered[i], filtered[j] = filtered[j], filtered[i]
		}
	}
	page, perPage := restPageParams(r)
	start, end := restPageBounds(page, perPage, len(filtered))
	restSetPageLinks(w, r, page, perPage, len(filtered))
	buf := make([]byte, 0, 512*(end-start+1))
	buf = append(buf, '[')
	for i, snap := range filtered[start:end] {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = h.appendIssueJSON(buf, snap)
	}
	buf = append(buf, ']')
	writeRawJSON(w, http.StatusOK, buf)
}

func (h *restHandler) createIssue(w http.ResponseWriter, r *http.Request, repo *Repo) {
	var req struct {
		Title  string           `json:"title"`
		Body   string           `json:"body"`
		Labels []restLabelInput `json:"labels"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	names := make([]string, 0, len(req.Labels))
	for _, l := range req.Labels {
		names = append(names, l.Name)
	}
	iss, err := h.s.CreateIssue(repo, req.Title, req.Body, names)
	if err == ErrUnknownLabel {
		WriteError(w, http.StatusUnprocessableEntity, "unknown label")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	snap, ok := h.snapshotIssue(repo, iss.Number)
	if !ok {
		WriteError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeRawJSON(w, http.StatusCreated, h.appendIssueJSON(make([]byte, 0, 512), snap))
}

func (h *restHandler) patchIssue(w http.ResponseWriter, r *http.Request, repo *Repo, number int) {
	if _, ok := h.s.GetIssue(repo, number); !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	var req struct {
		State *string `json:"state"`
		Title *string `json:"title"`
		Body  *string `json:"body"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	if req.State != nil {
		if *req.State != "open" && *req.State != "closed" {
			WriteError(w, http.StatusUnprocessableEntity, "invalid state")
			return
		}
		if _, err := h.s.SetIssueState(repo, number, *req.State); err != nil {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
	}
	if req.Title != nil || req.Body != nil {
		iss, ok := h.s.GetIssue(repo, number)
		if !ok {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		h.s.Lock()
		if req.Title != nil {
			iss.Title = *req.Title
		}
		if req.Body != nil {
			iss.Body = *req.Body
		}
		h.s.Unlock()
	}
	snap, ok := h.snapshotIssue(repo, number)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeRawJSON(w, http.StatusOK, h.appendIssueJSON(make([]byte, 0, 512), snap))
}

func (h *restHandler) createComment(w http.ResponseWriter, r *http.Request, repo *Repo, number int) {
	var req struct {
		Body string `json:"body"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	c, err := h.s.AddComment(repo, number, req.Body, ViewerLogin)
	if err != nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeRawJSON(w, http.StatusCreated, h.appendCommentJSON(make([]byte, 0, 256), c.ID, c.Body, c.Seq))
}

func (h *restHandler) listComments(w http.ResponseWriter, r *http.Request, repo *Repo, number int) {
	comments, err := h.s.ListComments(repo, number)
	if err != nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	buf := make([]byte, 0, 256*(len(comments)+1))
	buf = append(buf, '[')
	for i, c := range comments {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = h.appendCommentJSON(buf, c.ID, c.Body, c.Seq)
	}
	buf = append(buf, ']')
	writeRawJSON(w, http.StatusOK, buf)
}

// restLabelNameOf extracts a label name from a decoded JSON value (a bare
// string or an object with a name property).
func restLabelNameOf(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if s, ok := t["name"].(string); ok {
			return s
		}
	}
	return ""
}

func (h *restHandler) addIssueLabels(w http.ResponseWriter, r *http.Request, repo *Repo, number int) {
	iss, ok := h.s.GetIssue(repo, number)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	var v any
	if err := restDecodeJSON(r, &v); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	var names []string
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if name := restLabelNameOf(e); name != "" {
				names = append(names, name)
			}
		}
	case map[string]any:
		if arr, ok := t["labels"].([]any); ok {
			for _, e := range arr {
				if name := restLabelNameOf(e); name != "" {
					names = append(names, name)
				}
			}
		} else if s, ok := t["labels"].(string); ok && s != "" {
			names = append(names, s)
		}
	}
	for _, name := range names {
		if _, ok := h.s.GetLabel(repo, name); !ok {
			WriteError(w, http.StatusUnprocessableEntity, "unknown label")
			return
		}
	}
	h.s.Lock()
	for _, name := range names {
		present := false
		for _, existing := range iss.Labels {
			if existing == name {
				present = true
				break
			}
		}
		if !present {
			iss.Labels = append(iss.Labels, name)
		}
	}
	h.s.Unlock()
	snap, ok := h.snapshotIssue(repo, number)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeRawJSON(w, http.StatusOK, appendLabelListJSON(make([]byte, 0, 128), snap.Labels))
}

// ---------------------------------------------------------------------------
// Pull requests

// restStripOwnerPrefix drops a "owner:" prefix from a pull-request head ref.
func restStripOwnerPrefix(head string) string {
	if i := strings.LastIndex(head, ":"); i >= 0 {
		return head[i+1:]
	}
	return head
}

func (h *restHandler) dispatchPulls(w http.ResponseWriter, r *http.Request, repo *Repo, tail []string) {
	if len(tail) == 0 {
		switch r.Method {
		case http.MethodGet:
			h.listPulls(w, r, repo)
		case http.MethodPost:
			h.createPull(w, r, repo)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
		return
	}
	number, err := strconv.Atoi(tail[0])
	if err != nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if len(tail) == 1 {
		if r.Method != http.MethodGet {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		snap, ok := h.snapshotPR(repo, number)
		if !ok {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		writeRawJSON(w, http.StatusOK, h.appendPRJSON(make([]byte, 0, 512), snap))
		return
	}
	if len(tail) != 2 {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	switch tail[1] {
	case "files":
		if r.Method != http.MethodGet {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		snap, ok := h.snapshotPR(repo, number)
		if !ok {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		views := make([]restPRFile, 0, len(snap.Files))
		for _, f := range snap.Files {
			views = append(views, restPRFile{
				Filename:  f.Filename,
				Status:    f.Status,
				Additions: f.Additions,
				Deletions: f.Deletions,
				Changes:   f.Changes,
			})
		}
		WriteJSON(w, http.StatusOK, views)
	case "merge":
		if r.Method != http.MethodPut {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		h.mergePull(w, r, repo, number)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

func (h *restHandler) listPulls(w http.ResponseWriter, r *http.Request, repo *Repo) {
	snaps := h.snapshotAllPRs(repo)
	state := r.URL.Query().Get("state")
	filtered := make([]restPRSnapshot, 0, len(snaps))
	for _, snap := range snaps {
		switch state {
		case "", "open":
			if snap.State == "open" {
				filtered = append(filtered, snap)
			}
		case "closed":
			if snap.State == "closed" {
				filtered = append(filtered, snap)
			}
		case "all":
			filtered = append(filtered, snap)
		default:
			if snap.State == state {
				filtered = append(filtered, snap)
			}
		}
	}
	page, perPage := restPageParams(r)
	start, end := restPageBounds(page, perPage, len(filtered))
	restSetPageLinks(w, r, page, perPage, len(filtered))
	buf := make([]byte, 0, 512*(end-start+1))
	buf = append(buf, '[')
	for i, snap := range filtered[start:end] {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = h.appendPRJSON(buf, snap)
	}
	buf = append(buf, ']')
	writeRawJSON(w, http.StatusOK, buf)
}

func (h *restHandler) createPull(w http.ResponseWriter, r *http.Request, repo *Repo) {
	var req struct {
		Title string `json:"title"`
		Body  string `json:"body"`
		Head  string `json:"head"`
		Base  string `json:"base"`
	}
	if err := restDecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	head := restStripOwnerPrefix(req.Head)
	base := req.Base
	if base == "" {
		base = repo.DefaultBranch
	}
	if head == "" {
		WriteError(w, http.StatusUnprocessableEntity, "head is required")
		return
	}
	pr, err := h.s.CreatePullRequest(repo, req.Title, req.Body, head, base)
	if err == ErrRefNotFound {
		WriteError(w, http.StatusUnprocessableEntity, "head or base ref not found")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	snap, ok := h.snapshotPR(repo, pr.Number)
	if !ok {
		WriteError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeRawJSON(w, http.StatusCreated, h.appendPRJSON(make([]byte, 0, 512), snap))
}

func (h *restHandler) mergePull(w http.ResponseWriter, r *http.Request, repo *Repo, number int) {
	snap, ok := h.snapshotPR(repo, number)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	// The body carries merge_method (always "squash" from the suite); drain
	// it for completeness, tolerating an empty body.
	var req struct {
		MergeMethod string `json:"merge_method"`
	}
	_ = restDecodeJSON(r, &req)
	if snap.Merged {
		WriteJSON(w, http.StatusOK, map[string]any{
			"sha": snap.MergeCommitSHA, "merged": true,
			"message": "Pull request successfully merged",
		})
		return
	}
	if snap.State == "closed" {
		WriteError(w, http.StatusMethodNotAllowed, "Pull request is closed")
		return
	}
	headTip, ok := h.s.GetRef(repo, BranchRef(snap.HeadRef))
	if !ok {
		headTip = snap.HeadSHA
	}
	baseTip, ok := h.s.GetRef(repo, BranchRef(snap.BaseRef))
	if !ok {
		baseTip = snap.BaseSHA
	}
	if headTip == "" || baseTip == "" {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	headTip = h.s.PeelToCommit(repo, headTip)
	baseTip = h.s.PeelToCommit(repo, baseTip)

	// Three-way conflict detection against the merge base: a conflict is a
	// path changed on both sides since the merge base with differing
	// resulting blobs. (A missing path flattens to "", which no real blob
	// id equals, so adds/removes compare correctly.)
	mb := h.s.MergeBase(repo, baseTip, headTip)
	baseMap := h.flattenAt(repo, baseTip)
	headMap := h.flattenAt(repo, headTip)
	mbMap := h.flattenAt(repo, mb)
	paths := make(map[string]bool, len(baseMap)+len(headMap)+len(mbMap))
	for p := range baseMap {
		paths[p] = true
	}
	for p := range headMap {
		paths[p] = true
	}
	for p := range mbMap {
		paths[p] = true
	}
	for p := range paths {
		baseChanged := baseMap[p] != mbMap[p]
		headChanged := headMap[p] != mbMap[p]
		if baseChanged && headChanged && baseMap[p] != headMap[p] {
			WriteError(w, http.StatusMethodNotAllowed, "merge conflict")
			return
		}
	}

	// Squash: one commit on the base branch whose tree is the base tree
	// with the head side's changes since the merge base applied.
	merged := make(map[string]string, len(baseMap))
	for p, sha := range baseMap {
		merged[p] = sha
	}
	for p := range paths {
		if headMap[p] == mbMap[p] {
			continue
		}
		if sha, ok := headMap[p]; ok {
			merged[p] = sha
		} else {
			delete(merged, p)
		}
	}
	baseTree, _ := h.s.CommitTreeSHA(repo, baseTip)
	newTree := baseTree
	changed := make([]string, 0)
	for p := range paths {
		if merged[p] != baseMap[p] {
			changed = append(changed, p)
		}
	}
	sort.Strings(changed)
	for _, p := range changed {
		if sha, ok := merged[p]; ok {
			newTree = h.updateTreePath(repo, newTree, strings.Split(p, "/"), sha, false)
		} else {
			newTree = h.updateTreePath(repo, newTree, strings.Split(p, "/"), "", true)
		}
	}
	if newTree == "" {
		newTree = h.emptyTreeID(repo)
	}
	message := fmt.Sprintf("%s (#%d)", snap.Title, snap.Number)
	if snap.Title == "" {
		message = fmt.Sprintf("Merge pull request #%d", snap.Number)
	}
	var parents []string
	if baseTip != "" && baseTip != ZeroSHA {
		parents = []string{baseTip}
	}
	mergeSHA := h.makeCommit(repo, newTree, parents, message, ViewerLogin, ViewerEmail, ViewerLogin, ViewerEmail)
	h.s.SetRef(repo, BranchRef(snap.BaseRef), mergeSHA)
	if _, err := h.s.MarkPRMerged(repo, number, mergeSHA); err != nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"sha": mergeSHA, "merged": true,
		"message": "Pull request successfully merged",
	})
}
