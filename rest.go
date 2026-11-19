// rest.go — GitHub REST v3 handlers for the forge server.
//
// The router in main.go dispatches /api/v3 paths to the methods here. Auth is
// re-checked inside every handler through requireAuth (except the public API
// root), and the request-id header is set by the middleware in ServeHTTP, so
// handlers only have to write their own JSON bodies.
//
// Response views are built with small append-based encoders instead of
// reflection: the shapes are fixed, so plain byte appends are both faster and
// byte-stable. Request bodies are parsed exactly once from the
// middleware-stashed bytes (BodyBytes), never by re-reading the request.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// restBufPool hands out reusable byte buffers for response encoding.
var restBufPool = sync.Pool{New: func() any { return make([]byte, 0, 1024) }}

func restTakeBuf() []byte { return restBufPool.Get().([]byte)[:0] }

func restGiveBuf(b []byte) {
	if cap(b) <= 8192 {
		restBufPool.Put(b)
	}
}

// restWriteJSON writes a finished JSON document with the exact content type
// the API promises and an explicit length.
func restWriteJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// restWriteCommitSHA answers {"commit":{"sha": ...}} for content deletes.
func restWriteCommitSHA(w http.ResponseWriter, commitSHA string) {
	buf := restTakeBuf()
	buf = append(buf, `{"commit":{"sha":`...)
	buf = strconv.AppendQuote(buf, commitSHA)
	buf = append(buf, `}}`...)
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// restAppendUser writes {"login","id","type"} for the viewer.
func (a *App) restAppendUser(dst []byte, login string) []byte {
	dst = append(dst, `{"login":`...)
	dst = strconv.AppendQuote(dst, login)
	dst = append(dst, `,"id":`...)
	dst = strconv.AppendInt(dst, a.store.ViewerID(), 10)
	dst = append(dst, `,"type":"User"}`...)
	return dst
}

// restAppendRepo writes the repository view.
func (a *App) restAppendRepo(dst []byte, rp *Repo) []byte {
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendInt(dst, rp.ID, 10)
	dst = append(dst, `,"name":`...)
	dst = strconv.AppendQuote(dst, rp.Name)
	dst = append(dst, `,"full_name":`...)
	dst = strconv.AppendQuote(dst, rp.Owner+"/"+rp.Name)
	dst = append(dst, `,"owner":`...)
	dst = a.restAppendUser(dst, rp.Owner)
	dst = append(dst, `,"private":`...)
	dst = strconv.AppendBool(dst, rp.Private)
	dst = append(dst, `,"description":`...)
	if rp.Description == "" {
		dst = append(dst, "null"...)
	} else {
		dst = strconv.AppendQuote(dst, rp.Description)
	}
	dst = append(dst, `,"default_branch":`...)
	dst = strconv.AppendQuote(dst, rp.DefaultBranch)
	dst = append(dst, `,"permissions":{"admin":true,"maintain":true,"push":true,"triage":true,"pull":true},"created_at":`...)
	dst = strconv.AppendQuote(dst, rp.CreatedAt)
	dst = append(dst, `,"updated_at":`...)
	dst = strconv.AppendQuote(dst, rp.UpdatedAt)
	dst = append(dst, `,"has_issues":true,"fork":false,"archived":false}`...)
	return dst
}

// restAppendLabel writes {"id","name","color","description","default"}.
func restAppendLabel(dst []byte, lb *Label) []byte {
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendInt(dst, lb.ID, 10)
	dst = append(dst, `,"name":`...)
	dst = strconv.AppendQuote(dst, lb.Name)
	dst = append(dst, `,"color":`...)
	dst = strconv.AppendQuote(dst, lb.Color)
	dst = append(dst, `,"description":`...)
	dst = strconv.AppendQuote(dst, lb.Description)
	dst = append(dst, `,"default":false}`...)
	return dst
}

// restAppendIssue writes the issue view, resolving label names to objects.
func (a *App) restAppendIssue(dst []byte, rp *Repo, is *Issue) []byte {
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendInt(dst, is.ID, 10)
	dst = append(dst, `,"number":`...)
	dst = strconv.AppendInt(dst, int64(is.Number), 10)
	dst = append(dst, `,"title":`...)
	dst = strconv.AppendQuote(dst, is.Title)
	dst = append(dst, `,"body":`...)
	dst = strconv.AppendQuote(dst, is.Body)
	dst = append(dst, `,"state":`...)
	dst = strconv.AppendQuote(dst, is.State)
	dst = append(dst, `,"labels":[`...)
	for i, name := range is.Labels {
		if i > 0 {
			dst = append(dst, ',')
		}
		if lb := a.store.GetLabel(rp, name); lb != nil {
			dst = restAppendLabel(dst, lb)
		} else {
			dst = append(dst, `{"id":0,"name":`...)
			dst = strconv.AppendQuote(dst, name)
			dst = append(dst, `,"color":"","description":"","default":false}`...)
		}
	}
	dst = append(dst, `],"user":`...)
	dst = a.restAppendUser(dst, a.store.ViewerLogin())
	dst = append(dst, `,"comments":`...)
	dst = strconv.AppendInt(dst, int64(is.Comments), 10)
	dst = append(dst, `,"created_at":`...)
	dst = strconv.AppendQuote(dst, is.CreatedAt)
	dst = append(dst, `,"updated_at":`...)
	dst = strconv.AppendQuote(dst, is.UpdatedAt)
	dst = append(dst, `,"closed_at":`...)
	if is.State == "closed" {
		dst = strconv.AppendQuote(dst, is.UpdatedAt)
	} else {
		dst = append(dst, "null"...)
	}
	dst = append(dst, '}')
	return dst
}

// restAppendPull writes the pull request view. Head and base SHAs follow the
// live branch tips, falling back to the SHAs recorded at creation.
func (a *App) restAppendPull(dst []byte, rp *Repo, pr *Pull) []byte {
	headSHA := pr.HeadSHA
	if tip, ok := a.store.BranchTip(rp, pr.Head); ok {
		headSHA = tip
	}
	baseSHA := pr.BaseSHA
	if tip, ok := a.store.BranchTip(rp, pr.Base); ok {
		baseSHA = tip
	}
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendInt(dst, pr.ID, 10)
	dst = append(dst, `,"number":`...)
	dst = strconv.AppendInt(dst, int64(pr.Number), 10)
	dst = append(dst, `,"title":`...)
	dst = strconv.AppendQuote(dst, pr.Title)
	dst = append(dst, `,"body":`...)
	dst = strconv.AppendQuote(dst, pr.Body)
	dst = append(dst, `,"state":`...)
	dst = strconv.AppendQuote(dst, pr.State)
	dst = append(dst, `,"head":{"ref":`...)
	dst = strconv.AppendQuote(dst, pr.Head)
	dst = append(dst, `,"sha":`...)
	dst = strconv.AppendQuote(dst, headSHA)
	dst = append(dst, `,"label":`...)
	dst = strconv.AppendQuote(dst, rp.Owner+":"+pr.Head)
	dst = append(dst, `},"base":{"ref":`...)
	dst = strconv.AppendQuote(dst, pr.Base)
	dst = append(dst, `,"sha":`...)
	dst = strconv.AppendQuote(dst, baseSHA)
	dst = append(dst, `,"label":`...)
	dst = strconv.AppendQuote(dst, rp.Owner+":"+pr.Base)
	dst = append(dst, `},"merged":`...)
	dst = strconv.AppendBool(dst, pr.Merged)
	dst = append(dst, `,"merged_at":`...)
	if pr.MergedAt == "" {
		dst = append(dst, "null"...)
	} else {
		dst = strconv.AppendQuote(dst, pr.MergedAt)
	}
	dst = append(dst, `,"merge_commit_sha":`...)
	if pr.MergeSHA == "" {
		dst = append(dst, "null"...)
	} else {
		dst = strconv.AppendQuote(dst, pr.MergeSHA)
	}
	dst = append(dst, `,"user":`...)
	dst = a.restAppendUser(dst, a.store.ViewerLogin())
	dst = append(dst, `,"created_at":`...)
	dst = strconv.AppendQuote(dst, pr.CreatedAt)
	dst = append(dst, `,"updated_at":`...)
	dst = strconv.AppendQuote(dst, pr.UpdatedAt)
	dst = append(dst, '}')
	return dst
}

// restAppendContentFile writes the file view for one blob.
func restAppendContentFile(dst []byte, path string, data []byte, blobOID string) []byte {
	name := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		name = path[i+1:]
	}
	dst = append(dst, `{"type":"file","encoding":"base64","content":`...)
	dst = strconv.AppendQuote(dst, base64.StdEncoding.EncodeToString(data))
	dst = append(dst, `,"sha":`...)
	dst = strconv.AppendQuote(dst, blobOID)
	dst = append(dst, `,"size":`...)
	dst = strconv.AppendInt(dst, int64(len(data)), 10)
	dst = append(dst, `,"name":`...)
	dst = strconv.AppendQuote(dst, name)
	dst = append(dst, `,"path":`...)
	dst = strconv.AppendQuote(dst, path)
	dst = append(dst, '}')
	return dst
}

// restAppendDirEntry writes one entry of a directory listing.
func restAppendDirEntry(dst []byte, dirPath string, ent TreeEntry, size int) []byte {
	typ := "file"
	if restIsDirMode(ent.Mode) {
		typ = "dir"
	}
	p := ent.Name
	if dirPath != "" {
		p = dirPath + "/" + ent.Name
	}
	dst = append(dst, `{"type":`...)
	dst = strconv.AppendQuote(dst, typ)
	dst = append(dst, `,"name":`...)
	dst = strconv.AppendQuote(dst, ent.Name)
	dst = append(dst, `,"path":`...)
	dst = strconv.AppendQuote(dst, p)
	dst = append(dst, `,"sha":`...)
	dst = strconv.AppendQuote(dst, ent.OID)
	dst = append(dst, `,"size":`...)
	dst = strconv.AppendInt(dst, int64(size), 10)
	dst = append(dst, '}')
	return dst
}

// restAppendCommit writes {"sha","commit":{"message","author","committer"}}
// for the commits listing.
func (a *App) restAppendCommit(dst []byte, sha string, cm *Commit) []byte {
	dst = append(dst, `{"sha":`...)
	dst = strconv.AppendQuote(dst, sha)
	dst = append(dst, `,"commit":{"message":`...)
	dst = strconv.AppendQuote(dst, cm.Message)
	dst = append(dst, `,"author":`...)
	dst = restAppendPerson(dst, cm.Author, a.store.ViewerLogin())
	dst = append(dst, `,"committer":`...)
	dst = restAppendPerson(dst, cm.Committer, a.store.ViewerLogin())
	dst = append(dst, `}}`...)
	return dst
}

// restAppendPerson writes {"name","email","date"} from a raw author line.
func restAppendPerson(dst []byte, line, fallback string) []byte {
	name, email, date := restParsePersonLine(line, fallback)
	dst = append(dst, `{"name":`...)
	dst = strconv.AppendQuote(dst, name)
	dst = append(dst, `,"email":`...)
	dst = strconv.AppendQuote(dst, email)
	dst = append(dst, `,"date":`...)
	dst = strconv.AppendQuote(dst, date)
	dst = append(dst, '}')
	return dst
}

// restParsePersonLine splits "<login> <login>@example.invalid <unix> +0000".
func restParsePersonLine(line, fallback string) (name, email, date string) {
	name = fallback
	email = fallback + "@example.invalid"
	fields := strings.Fields(line)
	if len(fields) >= 4 {
		name = fields[0]
		email = fields[1]
		if unix, err := strconv.ParseInt(fields[2], 10, 64); err == nil {
			date = time.Unix(unix, 0).UTC().Format(time.RFC3339)
		}
	}
	return name, email, date
}

// restParseBody decodes the stashed request body into dst. A missing or
// broken body is a 400; the caller stops when this returns false.
func restParseBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw := BodyBytes(r)
	if len(raw) == 0 {
		WriteError(w, http.StatusBadRequest, "request body is empty")
		return false
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed JSON body")
		return false
	}
	return true
}

// restPageParams reads ?per_page= and ?page=, GitHub-style defaults included.
func restPageParams(r *http.Request) (perPage, page int) {
	perPage = 30
	page = 1
	q := r.URL.Query()
	if v := q.Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			perPage = n
		}
	}
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if perPage > 100 {
		perPage = 100
	}
	return perPage, page
}

// restPaginate slices one page out of a list; an out-of-range page is empty.
func restPaginate[T any](items []T, perPage, page int) []T {
	start := (page - 1) * perPage
	if start >= len(items) {
		return nil
	}
	end := start + perPage
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

// restLookupRepo enforces auth, the owner rule (a foreign owner is a 404,
// never a 403) and existence, writing the error reply when it fails.
func (a *App) restLookupRepo(w http.ResponseWriter, r *http.Request, owner, name string) *Repo {
	if !a.requireAuth(w, r) {
		return nil
	}
	if owner != a.token {
		WriteError(w, http.StatusNotFound, "Not Found")
		return nil
	}
	rp := a.store.GetRepo(owner, name)
	if rp == nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return nil
	}
	return rp
}

// handleREST is the one entry point the router in main.go calls for every
// /api/v3 path. It only parses method + path and hands off to the
// per-resource handlers; auth, the owner rule and existence checks live in
// those handlers (through restLookupRepo), and unknown shapes are 404 JSON.
func (a *App) handleREST(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/v3" || path == "/api/v3/":
		a.handleRestRoot(w, r)
		return
	case path == "/api/v3/meta":
		a.handleRestMeta(w, r)
		return
	case path == "/api/v3/user":
		a.handleUser(w, r)
		return
	case path == "/api/v3/user/repos":
		a.handleUserRepos(w, r)
		return
	}
	rest, found := strings.CutPrefix(path, "/api/v3/repos/")
	if !found {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	segs := strings.Split(rest, "/")
	if len(segs) < 2 || segs[0] == "" || segs[1] == "" {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	owner, repo := segs[0], segs[1]
	tail := segs[2:]
	if len(tail) == 0 {
		a.handleRepo(w, r, owner, repo)
		return
	}
	switch tail[0] {
	case "contents":
		a.handleContents(w, r, owner, repo, strings.Join(tail[1:], "/"))
	case "labels":
		if len(tail) == 1 {
			a.handleLabels(w, r, owner, repo)
		} else {
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	case "issues":
		switch {
		case len(tail) == 1:
			a.handleIssues(w, r, owner, repo)
		case len(tail) == 2:
			if n, err := strconv.Atoi(tail[1]); err == nil {
				a.handleIssue(w, r, owner, repo, n)
			} else {
				WriteError(w, http.StatusNotFound, "Not Found")
			}
		case len(tail) == 3 && tail[2] == "comments":
			if n, err := strconv.Atoi(tail[1]); err == nil {
				a.handleIssueComments(w, r, owner, repo, n)
			} else {
				WriteError(w, http.StatusNotFound, "Not Found")
			}
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	case "pulls":
		switch {
		case len(tail) == 1:
			a.handlePulls(w, r, owner, repo)
		case len(tail) == 2:
			if n, err := strconv.Atoi(tail[1]); err == nil {
				a.handlePull(w, r, owner, repo, n)
			} else {
				WriteError(w, http.StatusNotFound, "Not Found")
			}
		case len(tail) == 3 && tail[2] == "files":
			if n, err := strconv.Atoi(tail[1]); err == nil {
				a.handlePullFiles(w, r, owner, repo, n)
			} else {
				WriteError(w, http.StatusNotFound, "Not Found")
			}
		case len(tail) == 3 && tail[2] == "merge":
			if n, err := strconv.Atoi(tail[1]); err == nil {
				a.handlePullMerge(w, r, owner, repo, n)
			} else {
				WriteError(w, http.StatusNotFound, "Not Found")
			}
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	case "git":
		switch {
		case len(tail) == 2 && tail[1] == "refs":
			if r.Method == http.MethodPost {
				a.handleGitRefs(w, r, owner, repo)
			} else {
				a.handleGitRefsList(w, r, owner, repo)
			}
		case len(tail) == 4 && tail[1] == "refs" && tail[2] == "heads":
			a.handleGitRef(w, r, owner, repo, "refs/heads/"+tail[3])
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	case "branches":
		switch {
		case len(tail) == 1:
			a.handleBranches(w, r, owner, repo)
		case len(tail) == 2:
			a.handleBranch(w, r, owner, repo, tail[1])
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	case "commits":
		if len(tail) == 1 {
			a.handleCommits(w, r, owner, repo)
		} else {
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// handleUser answers GET /api/v3/user with the viewer view (auth required).
func (a *App) handleUser(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	buf := restTakeBuf()
	buf = a.restAppendUser(buf, a.store.ViewerLogin())
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// handleBranch answers GET /api/v3/repos/{owner}/{repo}/branches/{branch}
// with {"name","commit":{"sha"}}.
func (a *App) handleBranch(w http.ResponseWriter, r *http.Request, owner, repo, branch string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	tip, ok := a.store.BranchTip(rp, branch)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	buf := restTakeBuf()
	buf = append(buf, `{"name":`...)
	buf = strconv.AppendQuote(buf, branch)
	buf = append(buf, `,"commit":{"sha":`...)
	buf = strconv.AppendQuote(buf, tip)
	buf = append(buf, `}}`...)
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// handleGitRef answers GET /api/v3/repos/{owner}/{repo}/git/refs/{ref}
// (only refs/heads/<branch> is routed here) with the Git Data ref view.
func (a *App) handleGitRef(w http.ResponseWriter, r *http.Request, owner, repo, ref string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	oid, ok := a.store.GetRef(rp, ref)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	a.restWriteRef(w, ref, oid)
}

// handleGitRefsList answers GET /api/v3/repos/{owner}/{repo}/git/refs with
// every ref as {"ref","object":{"sha","type"}}.
func (a *App) handleGitRefsList(w http.ResponseWriter, r *http.Request, owner, repo string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	refs := a.store.ListRefs(rp)
	buf := restTakeBuf()
	buf = append(buf, '[')
	for i, ref := range refs {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = a.restAppendRef(buf, ref)
	}
	buf = append(buf, ']')
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// restAppendRef writes one {"ref","object":{"sha","type"}} entry.
func (a *App) restAppendRef(dst []byte, ref Ref) []byte {
	typ := "commit"
	dst = append(dst, `{"ref":`...)
	dst = strconv.AppendQuote(dst, ref.Name)
	dst = append(dst, `,"object":{"sha":`...)
	dst = strconv.AppendQuote(dst, ref.OID)
	dst = append(dst, `,"type":`...)
	dst = strconv.AppendQuote(dst, typ)
	dst = append(dst, `}}`...)
	return dst
}

// restWriteRef answers a single ref view.
func (a *App) restWriteRef(w http.ResponseWriter, ref, oid string) {
	buf := restTakeBuf()
	buf = a.restAppendRef(buf, Ref{Name: ref, OID: oid})
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// restRecordComment stores one comment body in the rest-side comment map
// (the store only keeps the count). The id is the store's running comment
// count for the issue, passed in by the caller, so REST and GraphQL writers
// agree on ids. This is the one place bodies are recorded.
func restRecordComment(owner, repo string, number, id int, body string) {
	key := restCommentKey(owner, repo, number)
	restCommentsMu.Lock()
	restComments[key] = append(restComments[key], restComment{ID: id, Body: body})
	restCommentsMu.Unlock()
}

// handleRestRoot answers GET /api/v3 with no auth, plus X-OAuth-Scopes.
func (a *App) handleRestRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	w.Header().Set("X-OAuth-Scopes", "repo, read:org")
	restWriteJSON(w, http.StatusOK, []byte(`{"current_user_url":"/api/v3/user","rate_limit_url":"/api/v3/rate_limit"}`))
}

// handleRestMeta answers GET /api/v3/meta (auth required).
func (a *App) handleRestMeta(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	restWriteJSON(w, http.StatusOK, []byte(`{"installed_version":"1.0.0"}`))
}

// handleUserRepos serves GET and POST /api/v3/user/repos.
func (a *App) handleUserRepos(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		perPage, page := restPageParams(r)
		all := a.store.ListRepos(a.token)
		if len(all) > page*perPage {
			next := "http://" + r.Host + "/api/v3/user/repos?per_page=" + strconv.Itoa(perPage) + "&page=" + strconv.Itoa(page+1)
			w.Header().Set("Link", "<"+next+`>; rel="next"`)
		}
		chunk := restPaginate(all, perPage, page)
		buf := restTakeBuf()
		buf = append(buf, '[')
		for i, rp := range chunk {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = a.restAppendRepo(buf, rp)
		}
		buf = append(buf, ']')
		restWriteJSON(w, http.StatusOK, buf)
		restGiveBuf(buf)
	case http.MethodPost:
		var in struct {
			Name        string `json:"name"`
			Private     bool   `json:"private"`
			Description string `json:"description"`
		}
		if !restParseBody(w, r, &in) {
			return
		}
		if strings.TrimSpace(in.Name) == "" {
			WriteError(w, 422, "name is required")
			return
		}
		rp, err := a.store.CreateRepo(a.token, in.Name, in.Description, in.Private)
		if err != nil {
			if errors.Is(err, ErrExists) {
				WriteError(w, 422, "Repository already exists")
			} else {
				WriteError(w, http.StatusBadRequest, err.Error())
			}
			return
		}
		buf := restTakeBuf()
		buf = a.restAppendRepo(buf, rp)
		restWriteJSON(w, http.StatusCreated, buf)
		restGiveBuf(buf)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// handleRepo serves GET, PATCH and DELETE /api/v3/repos/{owner}/{repo}.
func (a *App) handleRepo(w http.ResponseWriter, r *http.Request, owner, repo string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		buf := restTakeBuf()
		buf = a.restAppendRepo(buf, rp)
		restWriteJSON(w, http.StatusOK, buf)
		restGiveBuf(buf)
	case http.MethodPatch:
		var in struct {
			Description *string `json:"description"`
		}
		if !restParseBody(w, r, &in) {
			return
		}
		if in.Description != nil {
			updated, ok := a.store.UpdateRepo(owner, repo, *in.Description)
			if !ok {
				WriteError(w, http.StatusNotFound, "Not Found")
				return
			}
			rp = updated
		}
		buf := restTakeBuf()
		buf = a.restAppendRepo(buf, rp)
		restWriteJSON(w, http.StatusOK, buf)
		restGiveBuf(buf)
	case http.MethodDelete:
		if a.store.DeleteRepo(owner, repo) {
			w.WriteHeader(http.StatusNoContent)
		} else {
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// restIsDirMode reports whether a git tree entry mode is a directory.
func restIsDirMode(mode string) bool { return mode == "40000" || mode == "040000" }

// restIsHex reports whether s is a 40-character hex object id.
func restIsHex(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// restEmptyTreeOID is the id of the empty git tree, used when a delete
// empties a directory.
var restEmptyTreeOID = ObjectSHA("tree", nil)

// restResolveCommit turns a ?ref= value (branch name, full ref, tag name or
// commit sha) into a commit id. An empty ref means the default branch tip.
func (a *App) restResolveCommit(rp *Repo, ref string) (string, bool) {
	if ref == "" {
		return a.store.BranchTip(rp, rp.DefaultBranch)
	}
	if restIsHex(ref) {
		if o := a.store.GetObject(rp, ref); o != nil && o.Commit != nil {
			return ref, true
		}
	}
	if tip, ok := a.store.BranchTip(rp, ref); ok {
		return tip, true
	}
	oid, ok := a.store.GetRef(rp, ref)
	if !ok {
		oid, ok = a.store.GetRef(rp, "refs/tags/"+ref)
	}
	if !ok {
		return "", false
	}
	if o := a.store.GetObject(rp, oid); o != nil {
		if o.Tag != nil {
			return o.Tag.Object, true
		}
		if o.Commit != nil {
			return oid, true
		}
	}
	return "", false
}

// restTreeEntries returns the parsed entries of one tree object.
func (a *App) restTreeEntries(rp *Repo, treeOID string) []TreeEntry {
	if treeOID == "" {
		return nil
	}
	o := a.store.GetObject(rp, treeOID)
	if o == nil || o.Tree == nil {
		return nil
	}
	return o.Tree.Entries
}

// restWalkPath finds the tree entry for path under one commit.
func (a *App) restWalkPath(rp *Repo, commitSHA, path string) (TreeEntry, bool) {
	o := a.store.GetObject(rp, commitSHA)
	if o == nil || o.Commit == nil {
		return TreeEntry{}, false
	}
	cur := o.Commit.Tree
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var ent TreeEntry
	for i, part := range parts {
		if part == "" {
			return TreeEntry{}, false
		}
		hit := false
		for _, e := range a.restTreeEntries(rp, cur) {
			if e.Name == part {
				ent = e
				hit = true
				break
			}
		}
		if !hit {
			return TreeEntry{}, false
		}
		if i == len(parts)-1 {
			return ent, true
		}
		if !restIsDirMode(ent.Mode) {
			return TreeEntry{}, false
		}
		cur = ent.OID
	}
	return TreeEntry{}, false
}

// restWalkDir returns the entries of the directory at path ("" is the root)
// under one commit.
func (a *App) restWalkDir(rp *Repo, commitSHA, path string) ([]TreeEntry, bool) {
	o := a.store.GetObject(rp, commitSHA)
	if o == nil || o.Commit == nil {
		return nil, false
	}
	cur := o.Commit.Tree
	if strings.Trim(path, "/") == "" {
		return a.restTreeEntries(rp, cur), true
	}
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		hit := false
		for _, e := range a.restTreeEntries(rp, cur) {
			if e.Name == part && restIsDirMode(e.Mode) {
				cur = e.OID
				hit = true
				break
			}
		}
		if !hit {
			return nil, false
		}
	}
	return a.restTreeEntries(rp, cur), true
}

// restTreeSortKey orders tree entries the way git does: directories sort as
// if their name had a trailing slash.
func restTreeSortKey(e TreeEntry) string {
	if restIsDirMode(e.Mode) {
		return e.Name + "/"
	}
	return e.Name
}

// restEncodeTree stores a tree object for entries and returns its id.
func (a *App) restEncodeTree(rp *Repo, entries []TreeEntry) string {
	sorted := append([]TreeEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool {
		return restTreeSortKey(sorted[i]) < restTreeSortKey(sorted[j])
	})
	var raw []byte
	for _, e := range sorted {
		oid, err := hex.DecodeString(e.OID)
		if err != nil || len(oid) != 20 {
			continue
		}
		raw = append(raw, e.Mode...)
		raw = append(raw, ' ')
		raw = append(raw, e.Name...)
		raw = append(raw, 0)
		raw = append(raw, oid...)
	}
	return a.store.PutObject(rp, "tree", raw)
}

// restRebuildTree returns the id of the tree at treeOID with the leaf at
// parts replaced by blobOID (an empty blobOID removes the leaf). Intermediate
// directories are created or dropped as needed.
func (a *App) restRebuildTree(rp *Repo, treeOID string, parts []string, blobOID string) string {
	entries := append([]TreeEntry(nil), a.restTreeEntries(rp, treeOID)...)
	name := parts[0]
	if len(parts) == 1 {
		kept := entries[:0]
		found := false
		for _, e := range entries {
			if e.Name == name {
				found = true
				if blobOID != "" {
					e.Mode = "100644"
					e.OID = blobOID
					kept = append(kept, e)
				}
				continue
			}
			kept = append(kept, e)
		}
		if !found && blobOID != "" {
			kept = append(kept, TreeEntry{Mode: "100644", Name: name, OID: blobOID})
		}
		return a.restEncodeTree(rp, kept)
	}
	childOID := ""
	childIdx := -1
	for i, e := range entries {
		if e.Name == name && restIsDirMode(e.Mode) {
			childOID = e.OID
			childIdx = i
			break
		}
	}
	newChild := a.restRebuildTree(rp, childOID, parts[1:], blobOID)
	if newChild == childOID {
		return treeOID
	}
	if childIdx >= 0 {
		if newChild == restEmptyTreeOID && blobOID == "" {
			entries = append(entries[:childIdx], entries[childIdx+1:]...)
		} else {
			entries[childIdx].OID = newChild
		}
	} else if newChild != restEmptyTreeOID {
		entries = append(entries, TreeEntry{Mode: "40000", Name: name, OID: newChild})
	}
	return a.restEncodeTree(rp, entries)
}

// restCommitBranch writes one contents commit onto a branch: a blob (unless
// removing), a rebuilt root tree, and a commit whose parent is the branch
// tip, then moves the branch ref. It returns the commit and tree ids.
func (a *App) restCommitBranch(rp *Repo, branch, path, message string, data []byte, remove bool) (commitSHA, treeSHA string, err error) {
	tip, ok := a.store.BranchTip(rp, branch)
	if !ok {
		return "", "", ErrNotFound
	}
	cur := a.store.GetObject(rp, tip)
	if cur == nil || cur.Commit == nil {
		return "", "", ErrNotFound
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if remove {
		treeSHA = a.restRebuildTree(rp, cur.Commit.Tree, parts, "")
	} else {
		blobOID := a.store.PutObject(rp, "blob", data)
		treeSHA = a.restRebuildTree(rp, cur.Commit.Tree, parts, blobOID)
	}
	seq := a.store.NextSeq()
	unix := 1735689600 + int64(seq)
	login := a.store.ViewerLogin()
	line := login + " " + login + "@example.invalid " + strconv.FormatInt(unix, 10) + " +0000"
	var raw strings.Builder
	raw.WriteString("tree " + treeSHA + "\n")
	if tip != "" {
		raw.WriteString("parent " + tip + "\n")
	}
	raw.WriteString("author " + line + "\n")
	raw.WriteString("committer " + line + "\n\n")
	raw.WriteString(message)
	commitSHA = a.store.PutObject(rp, "commit", []byte(raw.String()))
	a.store.SetRef(rp, "refs/heads/"+branch, commitSHA)
	return commitSHA, treeSHA, nil
}

// handleContents serves GET, PUT and DELETE on
// /api/v3/repos/{owner}/{repo}/contents/{path...}.
func (a *App) handleContents(w http.ResponseWriter, r *http.Request, owner, repo, path string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.restContentsGet(w, r, rp, path)
	case http.MethodPut:
		a.restContentsPut(w, r, rp, path)
	case http.MethodDelete:
		a.restContentsDelete(w, r, rp, path)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

func (a *App) restContentsGet(w http.ResponseWriter, r *http.Request, rp *Repo, path string) {
	tip, ok := a.restResolveCommit(rp, r.URL.Query().Get("ref"))
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		a.restWriteDir(w, rp, tip, "")
		return
	}
	ent, found := a.restWalkPath(rp, tip, trimmed)
	if !found {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if restIsDirMode(ent.Mode) {
		a.restWriteDir(w, rp, tip, trimmed)
		return
	}
	obj := a.store.GetObject(rp, ent.OID)
	if obj == nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	buf := restTakeBuf()
	buf = restAppendContentFile(buf, trimmed, obj.Raw, ent.OID)
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// restWriteDir answers a directory listing as a JSON array.
func (a *App) restWriteDir(w http.ResponseWriter, rp *Repo, tip, dirPath string) {
	entries, ok := a.restWalkDir(rp, tip, dirPath)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	sorted := append([]TreeEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	buf := restTakeBuf()
	buf = append(buf, '[')
	for i, e := range sorted {
		if i > 0 {
			buf = append(buf, ',')
		}
		size := 0
		if !restIsDirMode(e.Mode) {
			if o := a.store.GetObject(rp, e.OID); o != nil {
				size = len(o.Raw)
			}
		}
		buf = restAppendDirEntry(buf, dirPath, e, size)
	}
	buf = append(buf, ']')
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

func (a *App) restContentsPut(w http.ResponseWriter, r *http.Request, rp *Repo, path string) {
	var in struct {
		Message string `json:"message"`
		Content string `json:"content"`
		SHA     string `json:"sha"`
		Branch  string `json:"branch"`
	}
	if !restParseBody(w, r, &in) {
		return
	}
	if in.Message == "" {
		WriteError(w, 422, "message is required")
		return
	}
	clean := strings.NewReplacer("\r", "", "\n", "", "\t", "", " ", "").Replace(in.Content)
	data, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "content is not valid base64")
		return
	}
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		WriteError(w, 422, "path is required")
		return
	}
	if in.Branch == "" {
		commitSHA, treeSHA, created, err := a.store.PutContent(rp, trimmed, data, in.Message, in.SHA)
		if err != nil {
			a.restContentsPutErr(w, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		a.restWritePutReply(w, status, in.Message, commitSHA, treeSHA, trimmed, data)
		return
	}
	tip, ok := a.store.BranchTip(rp, in.Branch)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	ent, found := a.restWalkPath(rp, tip, trimmed)
	if in.SHA != "" {
		if !found || ent.OID != in.SHA {
			WriteError(w, http.StatusConflict, "sha does not match")
			return
		}
	} else if found {
		WriteError(w, http.StatusConflict, "sha is required to update a file")
		return
	}
	commitSHA, treeSHA, err := a.restCommitBranch(rp, in.Branch, trimmed, in.Message, data, false)
	if err != nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	status := http.StatusOK
	if !found {
		status = http.StatusCreated
	}
	a.restWritePutReply(w, status, in.Message, commitSHA, treeSHA, trimmed, data)
}

func (a *App) restContentsPutErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrStaleSHA):
		WriteError(w, http.StatusConflict, "sha does not match")
	case errors.Is(err, ErrNotFound):
		WriteError(w, http.StatusNotFound, "Not Found")
	default:
		WriteError(w, http.StatusBadRequest, err.Error())
	}
}

// restWritePutReply answers {"commit":{"message","sha","tree":{"sha"}},"content":{...}}.
func (a *App) restWritePutReply(w http.ResponseWriter, status int, message, commitSHA, treeSHA, path string, data []byte) {
	blobOID := ObjectSHA("blob", data)
	buf := restTakeBuf()
	buf = append(buf, `{"commit":{"message":`...)
	buf = strconv.AppendQuote(buf, message)
	buf = append(buf, `,"sha":`...)
	buf = strconv.AppendQuote(buf, commitSHA)
	buf = append(buf, `,"tree":{"sha":`...)
	buf = strconv.AppendQuote(buf, treeSHA)
	buf = append(buf, `}},"content":`...)
	buf = restAppendContentFile(buf, path, data, blobOID)
	buf = append(buf, '}')
	restWriteJSON(w, status, buf)
	restGiveBuf(buf)
}

func (a *App) restContentsDelete(w http.ResponseWriter, r *http.Request, rp *Repo, path string) {
	var in struct {
		Message string `json:"message"`
		SHA     string `json:"sha"`
		Branch  string `json:"branch"`
	}
	if !restParseBody(w, r, &in) {
		return
	}
	if in.SHA == "" {
		WriteError(w, 422, "sha is required")
		return
	}
	trimmed := strings.Trim(path, "/")
	if in.Branch == "" {
		commitSHA, err := a.store.DeleteContent(rp, trimmed, in.Message, in.SHA)
		if err != nil {
			switch {
			case errors.Is(err, ErrStaleSHA):
				WriteError(w, http.StatusConflict, "sha does not match")
			case errors.Is(err, ErrNotFound):
				WriteError(w, http.StatusNotFound, "Not Found")
			default:
				WriteError(w, http.StatusBadRequest, err.Error())
			}
			return
		}
		restWriteCommitSHA(w, commitSHA)
		return
	}
	tip, ok := a.store.BranchTip(rp, in.Branch)
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	ent, found := a.restWalkPath(rp, tip, trimmed)
	if !found {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if ent.OID != in.SHA {
		WriteError(w, http.StatusConflict, "sha does not match")
		return
	}
	commitSHA, _, err := a.restCommitBranch(rp, in.Branch, trimmed, in.Message, nil, true)
	if err != nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	restWriteCommitSHA(w, commitSHA)
}

// handleLabels serves GET and POST /api/v3/repos/{owner}/{repo}/labels.
func (a *App) handleLabels(w http.ResponseWriter, r *http.Request, owner, repo string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.store.mu.RLock()
		list := make([]*Label, 0, len(rp.Labels))
		for _, lb := range rp.Labels {
			list = append(list, lb)
		}
		a.store.mu.RUnlock()
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		buf := restTakeBuf()
		buf = append(buf, '[')
		for i, lb := range list {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = restAppendLabel(buf, lb)
		}
		buf = append(buf, ']')
		restWriteJSON(w, http.StatusOK, buf)
		restGiveBuf(buf)
	case http.MethodPost:
		var in struct {
			Name        string `json:"name"`
			Color       string `json:"color"`
			Description string `json:"description"`
		}
		if !restParseBody(w, r, &in) {
			return
		}
		if strings.TrimSpace(in.Name) == "" {
			WriteError(w, 422, "name is required")
			return
		}
		if in.Color == "" {
			in.Color = "ededed"
		}
		lb, err := a.store.CreateLabel(rp, in.Name, in.Color, in.Description)
		if err != nil {
			if errors.Is(err, ErrExists) {
				WriteError(w, 422, "Label already exists")
			} else {
				WriteError(w, http.StatusBadRequest, err.Error())
			}
			return
		}
		buf := restTakeBuf()
		buf = restAppendLabel(buf, lb)
		restWriteJSON(w, http.StatusCreated, buf)
		restGiveBuf(buf)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// handleIssues serves GET and POST /api/v3/repos/{owner}/{repo}/issues.
func (a *App) handleIssues(w http.ResponseWriter, r *http.Request, owner, repo string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		state := q.Get("state")
		if state != "open" && state != "closed" {
			state = ""
		}
		list := a.store.ListIssues(rp, state)
		if strings.ToLower(q.Get("direction")) == "desc" {
			for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
				list[i], list[j] = list[j], list[i]
			}
		}
		perPage, page := restPageParams(r)
		chunk := restPaginate(list, perPage, page)
		buf := restTakeBuf()
		buf = append(buf, '[')
		for i, is := range chunk {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = a.restAppendIssue(buf, rp, is)
		}
		buf = append(buf, ']')
		restWriteJSON(w, http.StatusOK, buf)
		restGiveBuf(buf)
	case http.MethodPost:
		var in struct {
			Title  string   `json:"title"`
			Body   string   `json:"body"`
			Labels []string `json:"labels"`
		}
		if !restParseBody(w, r, &in) {
			return
		}
		if strings.TrimSpace(in.Title) == "" {
			WriteError(w, 422, "title is required")
			return
		}
		for _, name := range in.Labels {
			if a.store.GetLabel(rp, name) == nil {
				WriteError(w, 422, "Label does not exist: "+name)
				return
			}
		}
		is, err := a.store.CreateIssue(rp, in.Title, in.Body, in.Labels)
		if err != nil {
			if errors.Is(err, ErrUnknownLabel) {
				WriteError(w, 422, "Label does not exist")
			} else {
				WriteError(w, http.StatusBadRequest, err.Error())
			}
			return
		}
		buf := restTakeBuf()
		buf = a.restAppendIssue(buf, rp, is)
		restWriteJSON(w, http.StatusCreated, buf)
		restGiveBuf(buf)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// handleIssue serves GET and PATCH /api/v3/repos/{owner}/{repo}/issues/{n}.
func (a *App) handleIssue(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		is := a.store.GetIssue(rp, number)
		if is == nil {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		buf := restTakeBuf()
		buf = a.restAppendIssue(buf, rp, is)
		restWriteJSON(w, http.StatusOK, buf)
		restGiveBuf(buf)
	case http.MethodPatch:
		var in struct {
			State *string `json:"state"`
			Title *string `json:"title"`
			Body  *string `json:"body"`
		}
		if !restParseBody(w, r, &in) {
			return
		}
		is := a.store.GetIssue(rp, number)
		if is == nil {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		if in.State != nil && *in.State == "closed" && is.State != "closed" {
			closed, ok := a.store.CloseIssue(rp, number)
			if !ok {
				WriteError(w, http.StatusNotFound, "Not Found")
				return
			}
			is = closed
		}
		if in.State != nil && *in.State == "open" && is.State == "closed" {
			a.restReopenIssue(is)
		}
		if in.Title != nil || in.Body != nil {
			a.restEditIssue(is, in.Title, in.Body)
		}
		is = a.store.GetIssue(rp, number)
		if is == nil {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		buf := restTakeBuf()
		buf = a.restAppendIssue(buf, rp, is)
		restWriteJSON(w, http.StatusOK, buf)
		restGiveBuf(buf)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// restReopenIssue flips a closed issue back to open under the store lock.
// The store has no reopen call, so the field write happens here.
func (a *App) restReopenIssue(is *Issue) {
	seq := a.store.NextSeq()
	stamp := a.store.Timestamp(seq)
	a.store.mu.Lock()
	is.State = "open"
	is.UpdatedAt = stamp
	a.store.mu.Unlock()
}

// restEditIssue applies a title/body patch under the store lock.
func (a *App) restEditIssue(is *Issue, title, body *string) {
	seq := a.store.NextSeq()
	stamp := a.store.Timestamp(seq)
	a.store.mu.Lock()
	if title != nil {
		is.Title = *title
	}
	if body != nil {
		is.Body = *body
	}
	is.UpdatedAt = stamp
	a.store.mu.Unlock()
}

// restComment is one stored issue comment body. The store only counts
// comments, so rest.go keeps the bodies itself, keyed by repository and
// issue number; the comment id is the store's running count for the issue.
type restComment struct {
	ID   int
	Body string
}

var restCommentsMu sync.Mutex
var restComments = map[string][]restComment{}

func restCommentKey(owner, repo string, number int) string {
	return owner + "/" + repo + "#" + strconv.Itoa(number)
}

// handleIssueComments serves GET and POST on
// /api/v3/repos/{owner}/{repo}/issues/{n}/comments.
func (a *App) handleIssueComments(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if a.store.GetIssue(rp, number) == nil {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		restCommentsMu.Lock()
		list := append([]restComment(nil), restComments[restCommentKey(owner, repo, number)]...)
		restCommentsMu.Unlock()
		buf := restTakeBuf()
		buf = append(buf, '[')
		for i, c := range list {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = append(buf, `{"id":`...)
			buf = strconv.AppendInt(buf, int64(c.ID), 10)
			buf = append(buf, `,"body":`...)
			buf = strconv.AppendQuote(buf, c.Body)
			buf = append(buf, '}')
		}
		buf = append(buf, ']')
		restWriteJSON(w, http.StatusOK, buf)
		restGiveBuf(buf)
	case http.MethodPost:
		var in struct {
			Body string `json:"body"`
		}
		if !restParseBody(w, r, &in) {
			return
		}
		if in.Body == "" {
			WriteError(w, 422, "body is required")
			return
		}
		count, ok := a.store.AddComment(rp, number, in.Body)
		if !ok {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		restRecordComment(owner, repo, number, count, in.Body)
		buf := restTakeBuf()
		buf = append(buf, `{"id":`...)
		buf = strconv.AppendInt(buf, int64(count), 10)
		buf = append(buf, `,"body":`...)
		buf = strconv.AppendQuote(buf, in.Body)
		buf = append(buf, '}')
		restWriteJSON(w, http.StatusCreated, buf)
		restGiveBuf(buf)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// handleGitRefs serves POST /api/v3/repos/{owner}/{repo}/git/refs: create one
// ref (usually a branch) at an existing object.
func (a *App) handleGitRefs(w http.ResponseWriter, r *http.Request, owner, repo string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	var in struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}
	if !restParseBody(w, r, &in) {
		return
	}
	if in.Ref == "" || !strings.HasPrefix(in.Ref, "refs/") || in.SHA == "" {
		WriteError(w, 422, "ref and sha are required")
		return
	}
	obj := a.store.GetObject(rp, in.SHA)
	if obj == nil {
		WriteError(w, 422, "sha does not exist")
		return
	}
	if err := a.store.UpdateRefChecked(rp, in.Ref, "", in.SHA); err != nil {
		if errors.Is(err, ErrNotFound) {
			WriteError(w, http.StatusNotFound, "Not Found")
		} else {
			WriteError(w, 422, "Reference already exists")
		}
		return
	}
	buf := restTakeBuf()
	buf = append(buf, `{"ref":`...)
	buf = strconv.AppendQuote(buf, in.Ref)
	buf = append(buf, `,"object":{"sha":`...)
	buf = strconv.AppendQuote(buf, in.SHA)
	buf = append(buf, `,"type":`...)
	buf = strconv.AppendQuote(buf, obj.Type)
	buf = append(buf, `}}`...)
	restWriteJSON(w, http.StatusCreated, buf)
	restGiveBuf(buf)
}

// handleBranches serves GET /api/v3/repos/{owner}/{repo}/branches.
func (a *App) handleBranches(w http.ResponseWriter, r *http.Request, owner, repo string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	refs := a.store.ListRefs(rp)
	buf := restTakeBuf()
	buf = append(buf, '[')
	first := true
	for _, ref := range refs {
		if !strings.HasPrefix(ref.Name, "refs/heads/") {
			continue
		}
		if !first {
			buf = append(buf, ',')
		}
		first = false
		buf = append(buf, `{"name":`...)
		buf = strconv.AppendQuote(buf, strings.TrimPrefix(ref.Name, "refs/heads/"))
		buf = append(buf, `,"commit":{"sha":`...)
		buf = strconv.AppendQuote(buf, ref.OID)
		buf = append(buf, `}}`...)
	}
	buf = append(buf, ']')
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// handleCommits serves GET /api/v3/repos/{owner}/{repo}/commits[?sha=<ref>],
// walking ancestors newest-first from the resolved tip.
func (a *App) handleCommits(w http.ResponseWriter, r *http.Request, owner, repo string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	tip, ok := a.restResolveCommit(rp, r.URL.Query().Get("sha"))
	if !ok {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	seen := map[string]bool{}
	var order []string
	stack := []string{tip}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		obj := a.store.GetObject(rp, cur)
		if obj == nil || obj.Commit == nil {
			continue
		}
		order = append(order, cur)
		for i := len(obj.Commit.Parents) - 1; i >= 0; i-- {
			stack = append(stack, obj.Commit.Parents[i])
		}
	}
	perPage, page := restPageParams(r)
	chunk := restPaginate(order, perPage, page)
	buf := restTakeBuf()
	buf = append(buf, '[')
	for i, sha := range chunk {
		if i > 0 {
			buf = append(buf, ',')
		}
		obj := a.store.GetObject(rp, sha)
		buf = a.restAppendCommit(buf, sha, obj.Commit)
	}
	buf = append(buf, ']')
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// restListPulls copies the repo's pulls filtered by state ("open", "closed"
// or "" for all), in number order.
func (a *App) restListPulls(rp *Repo, state string) []*Pull {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	var out []*Pull
	for _, pr := range rp.Pulls {
		if state == "" || pr.State == state {
			out = append(out, pr)
		}
	}
	return out
}

// handlePulls serves GET and POST /api/v3/repos/{owner}/{repo}/pulls.
func (a *App) handlePulls(w http.ResponseWriter, r *http.Request, owner, repo string) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		state := q.Get("state")
		if state == "all" {
			state = ""
		} else if state != "closed" {
			state = "open"
		}
		list := a.restListPulls(rp, state)
		perPage, page := restPageParams(r)
		chunk := restPaginate(list, perPage, page)
		buf := restTakeBuf()
		buf = append(buf, '[')
		for i, pr := range chunk {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = a.restAppendPull(buf, rp, pr)
		}
		buf = append(buf, ']')
		restWriteJSON(w, http.StatusOK, buf)
		restGiveBuf(buf)
	case http.MethodPost:
		var in struct {
			Title string `json:"title"`
			Head  string `json:"head"`
			Base  string `json:"base"`
			Body  string `json:"body"`
		}
		if !restParseBody(w, r, &in) {
			return
		}
		if strings.TrimSpace(in.Title) == "" || in.Head == "" || in.Base == "" {
			WriteError(w, 422, "title, head and base are required")
			return
		}
		pr, err := a.store.CreatePull(rp, in.Title, in.Head, in.Base, in.Body)
		if err != nil {
			if errors.Is(err, ErrUnknownRef) {
				WriteError(w, 422, "head or base ref does not exist")
			} else {
				WriteError(w, http.StatusBadRequest, err.Error())
			}
			return
		}
		buf := restTakeBuf()
		buf = a.restAppendPull(buf, rp, pr)
		restWriteJSON(w, http.StatusCreated, buf)
		restGiveBuf(buf)
	default:
		WriteError(w, http.StatusNotFound, "Not Found")
	}
}

// handlePull serves GET /api/v3/repos/{owner}/{repo}/pulls/{n}.
func (a *App) handlePull(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	pr := a.store.GetPull(rp, number)
	if pr == nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	buf := restTakeBuf()
	buf = a.restAppendPull(buf, rp, pr)
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// restFlattenTree collects path -> blob id for every file under a tree.
func (a *App) restFlattenTree(rp *Repo, treeOID, prefix string, out map[string]string) {
	for _, e := range a.restTreeEntries(rp, treeOID) {
		p := e.Name
		if prefix != "" {
			p = prefix + "/" + e.Name
		}
		if restIsDirMode(e.Mode) {
			a.restFlattenTree(rp, e.OID, p, out)
		} else {
			out[p] = e.OID
		}
	}
}

// restSplitLines splits blob bytes into lines without a trailing empty one.
func restSplitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// restLineDiff counts added and removed lines between two blob versions,
// trimming the common prefix and suffix first.
func restLineDiff(oldData, newData []byte) (additions, deletions int) {
	oldLines := restSplitLines(oldData)
	newLines := restSplitLines(newData)
	p := 0
	for p < len(oldLines) && p < len(newLines) && oldLines[p] == newLines[p] {
		p++
	}
	s := 0
	for s < len(oldLines)-p && s < len(newLines)-p && oldLines[len(oldLines)-1-s] == newLines[len(newLines)-1-s] {
		s++
	}
	return len(newLines) - p - s, len(oldLines) - p - s
}

// handlePullFiles serves GET /api/v3/repos/{owner}/{repo}/pulls/{n}/files by
// diffing the base and head trees.
func (a *App) handlePullFiles(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	pr := a.store.GetPull(rp, number)
	if pr == nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	baseSHA := pr.BaseSHA
	if tip, ok := a.store.BranchTip(rp, pr.Base); ok {
		baseSHA = tip
	}
	headSHA := pr.HeadSHA
	if tip, ok := a.store.BranchTip(rp, pr.Head); ok {
		headSHA = tip
	}
	baseObj := a.store.GetObject(rp, baseSHA)
	headObj := a.store.GetObject(rp, headSHA)
	if baseObj == nil || baseObj.Commit == nil || headObj == nil || headObj.Commit == nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	baseFiles := map[string]string{}
	headFiles := map[string]string{}
	a.restFlattenTree(rp, baseObj.Commit.Tree, "", baseFiles)
	a.restFlattenTree(rp, headObj.Commit.Tree, "", headFiles)
	names := make([]string, 0, len(baseFiles)+len(headFiles))
	seen := map[string]bool{}
	for name := range baseFiles {
		names = append(names, name)
		seen[name] = true
	}
	for name := range headFiles {
		if !seen[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	buf := restTakeBuf()
	buf = append(buf, '[')
	first := true
	for _, name := range names {
		oldOID, inBase := baseFiles[name]
		newOID, inHead := headFiles[name]
		if inBase && inHead && oldOID == newOID {
			continue
		}
		status := "modified"
		var oldData, newData []byte
		if !inBase {
			status = "added"
		} else if !inHead {
			status = "removed"
		}
		if inBase {
			if o := a.store.GetObject(rp, oldOID); o != nil {
				oldData = o.Raw
			}
		}
		if inHead {
			if o := a.store.GetObject(rp, newOID); o != nil {
				newData = o.Raw
			}
		}
		additions, deletions := restLineDiff(oldData, newData)
		sha := newOID
		if !inHead {
			sha = oldOID
		}
		if !first {
			buf = append(buf, ',')
		}
		first = false
		buf = append(buf, `{"filename":`...)
		buf = strconv.AppendQuote(buf, name)
		buf = append(buf, `,"status":`...)
		buf = strconv.AppendQuote(buf, status)
		buf = append(buf, `,"additions":`...)
		buf = strconv.AppendInt(buf, int64(additions), 10)
		buf = append(buf, `,"deletions":`...)
		buf = strconv.AppendInt(buf, int64(deletions), 10)
		buf = append(buf, `,"changes":`...)
		buf = strconv.AppendInt(buf, int64(additions+deletions), 10)
		buf = append(buf, `,"sha":`...)
		buf = strconv.AppendQuote(buf, sha)
		buf = append(buf, '}')
	}
	buf = append(buf, ']')
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}

// handlePullMerge serves PUT /api/v3/repos/{owner}/{repo}/pulls/{n}/merge.
// A conflicted or already-merged pull is a 405; an unknown pull is a 404.
func (a *App) handlePullMerge(w http.ResponseWriter, r *http.Request, owner, repo string, number int) {
	rp := a.restLookupRepo(w, r, owner, repo)
	if rp == nil {
		return
	}
	if r.Method != http.MethodPut {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if raw := BodyBytes(r); len(raw) > 0 {
		var probe struct {
			MergeMethod string `json:"merge_method"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			WriteError(w, http.StatusBadRequest, "malformed JSON body")
			return
		}
	}
	if a.store.GetPull(rp, number) == nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	sha, err := a.store.MergePull(rp, number)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			WriteError(w, http.StatusNotFound, "Not Found")
		case errors.Is(err, ErrAlreadyMerged), errors.Is(err, ErrConflict):
			WriteError(w, 405, err.Error())
		default:
			WriteError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	buf := restTakeBuf()
	buf = append(buf, `{"sha":`...)
	buf = strconv.AppendQuote(buf, sha)
	buf = append(buf, `,"merged":true,"message":"Pull Request successfully merged"}`...)
	restWriteJSON(w, http.StatusOK, buf)
	restGiveBuf(buf)
}
