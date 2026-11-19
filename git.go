// Git smart-HTTP surface: protocol v2 and v0 upload-pack, v0 receive-pack.
//
// Wire behavior follows the git smart-HTTP protocol as exercised by the
// conformance client:
//
//   - info/refs answers v2 capabilities when the request carries
//     "Git-Protocol: version=2" (upload-pack only) and a v0 ref advertisement
//     otherwise, with symref HEAD, peeled annotated tags, and the empty-repo
//     capabilities^{} pseudo-ref.
//   - v2 ls-refs filters server-side by ref-prefix and reports symrefs and
//     peeled tags on request.
//   - v2/v0 fetch negotiates want/have, honours shallow/deepen (the client's
//     shallow boundary stops the have-walk, so deepen delivers exactly the
//     next generation), and always frames the packfile section in sideband
//     (band 1 = pack data), which the client requires even for v2.
//   - receive-pack unpacks the pack (deltas resolved, trailer verified),
//     stores the objects, then applies each ref command with strict
//     fast-forward rules, reporting per-ref ok/ng inside sideband band 1
//     when negotiated.
//
// A push never invents a repo: every git path 404s when the repo does not
// exist. Handlers override Content-Type before writing: git bodies are
// binary, not JSON.
//
// Performance shape (the v2 rebuild): nothing on the read path copies the
// whole object map per request. Fetches run off the store's cached
// immutable snapshot (Store.Snapshot: one copy per repo generation, then
// the same pointer for every request), and the built pack bytes come from
// the pack cache keyed by (generation, wants, haves, depth), so the 50
// concurrent depth-1 clones of one tip build the pack exactly once.
// Advertisements and ls-refs are refs-only: they read the sorted ref list
// and resolve tag peels one object at a time, never touching the object
// map. Pushed objects go in through the store's batch insert (one lock,
// SHAs already computed by the pack parser, no re-hash).

package main

import (
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ParseGitPath splits "/{owner}/{repo}.git/{rest...}" into owner, repo (the
// ".git" suffix stripped), and the rest of the path. It reports false when
// the path is not a git smart-HTTP path.
func ParseGitPath(path string) (owner, repo, rest string, ok bool) {
	trimmed := strings.TrimPrefix(path, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 || parts[0] == "" || !strings.HasSuffix(parts[1], ".git") {
		return "", "", "", false
	}
	return parts[0], strings.TrimSuffix(parts[1], ".git"), strings.Join(parts[2:], "/"), true
}

// Capabilities advertised on the first line of a v0 ref advertisement.
// Upload-pack must offer side-band-64k (fetch framing) and shallow (v0
// shallow fetch); receive-pack must offer report-status, side-band-64k and
// delete-refs. report-status-v2 is deliberately not offered: the client
// prefers it when present, and plain report-status is what is implemented.
const (
	gitUploadPackCaps  = "side-band-64k multi_ack multi_ack_detailed thin-pack ofs-delta shallow agent=forge/1.0 object-format=sha1 symref=HEAD:refs/heads/main"
	gitReceivePackCaps = "report-status side-band-64k delete-refs ofs-delta agent=forge/1.0 object-format=sha1 symref=HEAD:refs/heads/main"
)

// RegisterGit registers the git smart-HTTP routes on mux.
func RegisterGit(mux *Router, s *Store) {
	mux.Handle(func(r *http.Request, path string) bool {
		_, _, _, ok := ParseGitPath(path)
		return ok
	}, func(w http.ResponseWriter, r *http.Request) {
		owner, repoName, rest, _ := ParseGitPath(pathOf(r))
		repo, exists := s.GetRepo(owner, repoName)
		if !exists {
			WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		switch {
		case rest == "info/refs" && r.Method == http.MethodGet:
			gitHandleInfoRefs(w, r, repo, s)
		case rest == "git-upload-pack" && r.Method == http.MethodPost:
			gitHandleUploadPack(w, r, repo, s)
		case rest == "git-receive-pack" && r.Method == http.MethodPost:
			gitHandleReceivePack(w, r, repo, s)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
	})
}

// gitPackCache memoizes built pack bytes across requests. It is keyed by
// repo generation, so a repo change can never serve a stale pack; entries
// are bounded inside the cache itself.
var gitPackCache = NewPackCache()

// peelWithStore follows annotated tag objects to their ultimate target (up
// to 16 hops) through the live store. Non-tag ids pass through unchanged.
// It is the peel used by the refs-only paths, which hold no object map.
func peelWithStore(s *Store, r *Repo, oid string) string {
	for i := 0; i < 16; i++ {
		obj, ok := s.GetObject(r, oid)
		if !ok || obj == nil || obj.Type != ObjTag || obj.Tag == nil {
			return oid
		}
		oid = obj.Tag.Object
	}
	return oid
}

// snapshotPeel follows annotated tag objects inside a snapshot's object
// map (up to 16 hops). Non-tag ids pass through unchanged.
func snapshotPeel(snap *RepoSnapshot, oid string) string {
	for i := 0; i < 16; i++ {
		obj := snap.Objects[oid]
		if obj == nil || obj.Type != ObjTag || obj.Tag == nil {
			return oid
		}
		oid = obj.Tag.Object
	}
	return oid
}

// --- pkt-line output helpers -----------------------------------------------

var gitHexDigits = []byte("0123456789abcdef")

// gitBufPool recycles the scratch buffers response bodies are assembled in.
// Bodies that escape into a cache are never pooled; only the transient
// assembly buffers come from here. Oversized buffers are dropped instead
// of retained.
var gitBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

func takeGitBuf() *[]byte {
	return gitBufPool.Get().(*[]byte)
}

func releaseGitBuf(b *[]byte) {
	if cap(*b) <= 1<<20 {
		*b = (*b)[:0]
		gitBufPool.Put(b)
	}
}

// appendHexLen appends n as a 4-hex-digit pkt-line length.
func appendHexLen(dst []byte, n int) []byte {
	return append(dst,
		gitHexDigits[(n>>12)&0xf],
		gitHexDigits[(n>>8)&0xf],
		gitHexDigits[(n>>4)&0xf],
		gitHexDigits[n&0xf],
	)
}

// appendPkt appends one pkt-line framing payload.
func appendPkt(dst, payload []byte) []byte {
	dst = appendHexLen(dst, len(payload)+4)
	return append(dst, payload...)
}

// appendPktText appends one pkt-line framing s, without copying s first.
func appendPktText(dst []byte, s string) []byte {
	dst = appendHexLen(dst, len(s)+4)
	return append(dst, s...)
}

// appendFlush appends a flush packet.
func appendFlush(dst []byte) []byte {
	return append(dst, '0', '0', '0', '0')
}

// gitSidebandChunk is the largest pack-data chunk per sideband packet: the
// 65,520-byte pkt-line limit minus the 4-byte length header and the band byte.
const gitSidebandChunk = 65515

// appendSideband appends data as band-1 sideband packets.
func appendSideband(dst, data []byte) []byte {
	for len(data) > 0 {
		n := len(data)
		if n > gitSidebandChunk {
			n = gitSidebandChunk
		}
		dst = appendHexLen(dst, 4+1+n)
		dst = append(dst, 1)
		dst = append(dst, data[:n]...)
		data = data[n:]
	}
	return dst
}

// gitWriteBinary answers 200 with a fully built binary body, overriding the
// middleware's JSON content type.
func gitWriteBinary(w http.ResponseWriter, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// --- info/refs ---------------------------------------------------------------

func gitHandleInfoRefs(w http.ResponseWriter, r *http.Request, repo *Repo, s *Store) {
	service := r.URL.Query().Get("service")
	if service != "git-upload-pack" && service != "git-receive-pack" {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if service == "git-upload-pack" && strings.Contains(r.Header.Get("Git-Protocol"), "version=2") {
		// The v2 advertisement is constant: no refs, no object map, no copy.
		gitWriteBinary(w, "application/x-git-upload-pack-advertisement", v2AdvertisementBytes)
		return
	}
	// v0 advertisements list refs only: the sorted ref list is enough, and
	// tag peeling goes through the store one object at a time.
	buf := takeGitBuf()
	defer releaseGitBuf(buf)
	caps := gitUploadPackCaps
	ctype := "application/x-git-upload-pack-advertisement"
	if service != "git-upload-pack" {
		caps = gitReceivePackCaps
		ctype = "application/x-git-receive-pack-advertisement"
	}
	*buf = buildV0Advertisement(*buf, s, repo, s.ListRefs(repo), service, caps)
	gitWriteBinary(w, ctype, *buf)
}

// v2AdvertisementBytes is the protocol v2 capability advertisement, built
// once: it never varies per repo. The fetch capability must name shallow
// (the client refuses shallow fetches otherwise). ls-refs is advertised
// bare: advertising unborn would make the client request unborn lines, and
// an unborn refs/heads/main line would read as a real ref on an empty repo.
var v2AdvertisementBytes = func() []byte {
	var out []byte
	out = appendPktText(out, "version 2\n")
	out = appendPktText(out, "fetch=shallow\n")
	out = appendPktText(out, "ls-refs\n")
	out = appendPktText(out, "object-format=sha1\n")
	out = appendPktText(out, "agent=forge/1.0\n")
	out = appendFlush(out)
	return out
}()

// buildV0Advertisement renders a v0 ref advertisement into dst: the service
// preamble and flush, then HEAD (when the default branch exists), every ref
// sorted by name with peeled tag lines, capabilities on the first line. An
// empty repo advertises only the capabilities^{} pseudo-ref at the zero id.
func buildV0Advertisement(dst []byte, s *Store, r *Repo, refs []RefEntry, service, caps string) []byte {
	dst = appendPktText(dst, "# service="+service+"\n")
	dst = appendFlush(dst)
	type refLine struct{ oid, name string }
	lines := make([]refLine, 0, len(refs)+1)
	for _, e := range refs {
		if e.Name == BranchRef(DefaultBranch) {
			lines = append(lines, refLine{e.SHA, "HEAD"})
			break
		}
	}
	for _, e := range refs {
		lines = append(lines, refLine{e.SHA, e.Name})
		if obj, ok := s.GetObject(r, e.SHA); ok && obj != nil && obj.Type == ObjTag {
			if peeled := peelWithStore(s, r, e.SHA); peeled != e.SHA {
				lines = append(lines, refLine{peeled, e.Name + "^{}"})
			}
		}
	}
	if len(lines) == 0 {
		dst = appendPktText(dst, ZeroSHA+" capabilities^{}\x00"+caps+"\n")
	} else {
		for i, ln := range lines {
			text := ln.oid + " " + ln.name
			if i == 0 {
				text += "\x00" + caps
			}
			dst = appendPktText(dst, text+"\n")
		}
	}
	dst = appendFlush(dst)
	return dst
}

// --- upload-pack -------------------------------------------------------------

func gitHandleUploadPack(w http.ResponseWriter, r *http.Request, repo *Repo, s *Store) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "cannot read request body")
		return
	}
	lines, err := DecodePktLines(body)
	if err != nil {
		// Malformed input must never take the server down: answer 400 and
		// leave the repo untouched.
		WriteError(w, http.StatusBadRequest, "malformed pkt-line stream")
		return
	}
	isV2 := strings.Contains(r.Header.Get("Git-Protocol"), "version=2")
	if !isV2 {
		for _, ln := range lines {
			if ln.Flush || ln.Delim || ln.End {
				continue
			}
			if strings.HasPrefix(string(ln.Payload), "command=") {
				isV2 = true
			}
			break
		}
	}
	// One cached snapshot serves the whole fetch request. ls-refs never
	// takes one: it is a refs-only command and must not pay for an
	// object-map copy on first use after a mutation.
	buf := takeGitBuf()
	defer releaseGitBuf(buf)
	var resp []byte
	if isV2 && v2Command(lines) == "ls-refs" {
		resp, err = handleV2(s, repo, nil, lines, buf)
	} else if isV2 {
		resp, err = handleV2(s, repo, s.Snapshot(repo), lines, buf)
	} else {
		resp, err = handleV0Fetch(s.Snapshot(repo), lines, buf)
	}
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	gitWriteBinary(w, "application/x-git-upload-pack-result", resp)
}

// v2Command extracts the command= line from a v2 request's pre-delim
// section, or "" when there is none.
func v2Command(lines []PktLine) string {
	for _, ln := range lines {
		switch {
		case ln.Flush, ln.End:
		case ln.Delim:
			return ""
		default:
			text := strings.TrimSuffix(string(ln.Payload), "\n")
			if strings.HasPrefix(text, "command=") {
				return text[len("command="):]
			}
		}
	}
	return ""
}

// handleV2 dispatches a v2 request: the command and its arguments are
// split by the delim packet.
func handleV2(s *Store, r *Repo, snap *RepoSnapshot, lines []PktLine, buf *[]byte) ([]byte, error) {
	command := ""
	var args []string
	seenDelim := false
	for _, ln := range lines {
		switch {
		case ln.Flush, ln.End:
		case ln.Delim:
			seenDelim = true
		default:
			text := strings.TrimSuffix(string(ln.Payload), "\n")
			if !seenDelim {
				if strings.HasPrefix(text, "command=") {
					command = text[len("command="):]
				}
				// agent= and object-format= lines are accepted and ignored.
			} else {
				args = append(args, text)
			}
		}
	}
	switch command {
	case "ls-refs":
		return lsRefsV2(s, r, args, buf), nil
	case "fetch":
		return fetchV2(snap, args, buf)
	default:
		return nil, errors.New("unknown or missing v2 command")
	}
}

// lsRefsV2 answers ls-refs from the refs-only view: one line per matching
// ref, "<oid> <name>" with symref-target on HEAD and peeled on annotated
// tags, when requested. Prefix filtering is server-side and applies to HEAD
// too: HEAD is only listed when it matches a prefix (or no prefix was
// given). Tag peels resolve through the store one object at a time.
func lsRefsV2(s *Store, r *Repo, args []string, buf *[]byte) []byte {
	peel, symrefs, unborn := false, false, false
	var prefixes []string
	for _, a := range args {
		switch {
		case a == "peel":
			peel = true
		case a == "symrefs":
			symrefs = true
		case a == "unborn":
			unborn = true
		case strings.HasPrefix(a, "ref-prefix "):
			prefixes = append(prefixes, a[len("ref-prefix "):])
		}
	}
	matches := func(name string) bool {
		if len(prefixes) == 0 {
			return true
		}
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
		return false
	}
	refs := s.ListRefs(r)
	out := *buf
	if symrefs && matches("HEAD") {
		mainTip := ""
		for _, e := range refs {
			if e.Name == BranchRef(DefaultBranch) {
				mainTip = e.SHA
				break
			}
		}
		if mainTip != "" {
			out = appendPktText(out, mainTip+" HEAD symref-target:"+BranchRef(DefaultBranch)+"\n")
		} else if unborn {
			out = appendPktText(out, "unborn HEAD symref-target:"+BranchRef(DefaultBranch)+"\n")
		}
	}
	for _, e := range refs {
		if !matches(e.Name) {
			continue
		}
		text := e.SHA + " " + e.Name
		if peel {
			if obj, ok := s.GetObject(r, e.SHA); ok && obj != nil && obj.Type == ObjTag {
				if peeled := peelWithStore(s, r, e.SHA); peeled != e.SHA {
					text += " peeled:" + peeled
				}
			}
		}
		out = appendPktText(out, text+"\n")
	}
	out = appendFlush(out)
	*buf = out
	return *buf
}

// fetchRequest is a parsed fetch negotiation: wants, haves, the client's
// current shallow boundary, and an optional deepen depth.
type fetchRequest struct {
	wants    []string
	haves    []string
	shallow  []string
	depth    int
	hasDepth bool
}

// parseFetchArgs parses want/have/shallow/deepen lines from either a v2
// argument list or a v0 request body. Negotiation-only lines (thin-pack,
// no-progress, ofs-delta, done, filter, deepen-since, deepen-not) are
// accepted and ignored.
func parseFetchArgs(args []string) fetchRequest {
	var req fetchRequest
	for _, arg := range args {
		fields := strings.Fields(arg)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "want":
			if len(fields) >= 2 {
				req.wants = append(req.wants, fields[1])
			}
		case "have":
			if len(fields) >= 2 {
				req.haves = append(req.haves, fields[1])
			}
		case "shallow":
			if len(fields) >= 2 {
				req.shallow = append(req.shallow, fields[1])
			}
		case "deepen":
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil && n > 0 {
					req.depth = n
					req.hasDepth = true
				}
			}
		}
	}
	return req
}

// fetchPlan is the negotiated fetch result: ACKs, the new shallow
// boundary, boundary commits that stopped being shallow, and the pack.
type fetchPlan struct {
	acks      []string
	shallow   []string
	unshallow []string
	pack      []byte
}

// planFetch computes the objects to send and the negotiation outcome. The
// pack holds exactly the objects reachable from the wants (within the
// deepen depth, when given) minus the objects the client already holds.
// The pack bytes come from the pack cache whenever the negotiation has no
// client shallow boundary: the cache key (generation, wants, haves,
// depth) covers everything the pack depends on, and concurrent clones of
// one tip share a single build. A request that carries a shallow boundary
// bypasses the cache, because the boundary also shapes the pack and the
// key carries no shallow component.
func planFetch(snap *RepoSnapshot, req fetchRequest) (*fetchPlan, error) {
	plan := &fetchPlan{}
	include, commitDist := walkWants(snap, req)
	exclude := walkHaves(snap, req)
	objects := make([]*GitObject, 0, len(include))
	for oid := range include {
		if exclude[oid] {
			continue
		}
		if obj, ok := snap.Objects[oid]; ok {
			objects = append(objects, obj)
		}
	}
	// Fixed order: sorted by id, so identical object sets pack identically.
	sort.Slice(objects, func(i, j int) bool { return objects[i].SHA < objects[j].SHA })
	depth := 0
	if req.hasDepth {
		depth = req.depth
	}
	var err error
	if len(req.shallow) == 0 {
		key := PackCacheKeyFor(snap.Generation, req.wants, req.haves, depth)
		plan.pack, err = gitPackCache.GetOrBuild(key, func() ([]byte, error) {
			return BuildPack(objects)
		})
	} else {
		plan.pack, err = BuildPack(objects)
	}
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(req.haves))
	for _, h := range req.haves {
		if seen[h] {
			continue
		}
		seen[h] = true
		if _, ok := snap.Objects[h]; ok {
			plan.acks = append(plan.acks, h)
		}
	}
	if req.hasDepth {
		boundarySet := make(map[string]bool)
		for oid := range commitDist {
			obj := snap.Objects[oid]
			if obj == nil || obj.Commit == nil || len(obj.Commit.Parents) == 0 {
				continue
			}
			cut := true
			for _, p := range obj.Commit.Parents {
				if _, ok := commitDist[p]; ok {
					cut = false
					break
				}
			}
			if cut {
				boundarySet[oid] = true
				plan.shallow = append(plan.shallow, oid)
			}
		}
		sort.Strings(plan.shallow)
		seenUn := make(map[string]bool)
		for _, b := range req.shallow {
			if seenUn[b] {
				continue
			}
			seenUn[b] = true
			if _, ok := commitDist[b]; ok && !boundarySet[b] {
				plan.unshallow = append(plan.unshallow, b)
			}
		}
		sort.Strings(plan.unshallow)
	}
	return plan, nil
}

// walkWants returns the objects reachable from the wants: every included
// object id, plus the generation distance of every included commit (want
// commits at distance 0). Tag wants contribute the tag chain plus the peeled
// target. With a deepen depth, only commits closer than depth generations
// are included; their trees and blobs are always included in full.
func walkWants(snap *RepoSnapshot, req fetchRequest) (map[string]bool, map[string]int) {
	include := make(map[string]bool)
	commitDist := make(map[string]int)
	type queueItem struct {
		oid  string
		dist int
	}
	queue := make([]queueItem, 0, len(req.wants))
	head := 0
	for _, want := range req.wants {
		cur := want
		for i := 0; i < 17; i++ {
			obj := snap.Objects[cur]
			if obj == nil || obj.Type != ObjTag || obj.Tag == nil {
				break
			}
			include[cur] = true
			cur = obj.Tag.Object
		}
		obj := snap.Objects[cur]
		if obj == nil {
			continue
		}
		switch obj.Type {
		case ObjCommit:
			if _, ok := commitDist[cur]; !ok {
				commitDist[cur] = 0
				queue = append(queue, queueItem{cur, 0})
			}
		case ObjTree:
			addTreeClosure(snap, cur, include)
		case ObjBlob:
			include[cur] = true
		}
	}
	for head < len(queue) {
		it := queue[head]
		head++
		if d, ok := commitDist[it.oid]; !ok || d != it.dist {
			continue
		}
		obj := snap.Objects[it.oid]
		if obj == nil || obj.Commit == nil {
			continue
		}
		include[it.oid] = true
		addTreeClosure(snap, obj.Commit.Tree, include)
		if req.hasDepth && it.dist+1 >= req.depth {
			continue
		}
		for _, p := range obj.Commit.Parents {
			if _, ok := snap.Objects[p]; !ok {
				continue
			}
			nd := it.dist + 1
			if d, ok := commitDist[p]; ok && d <= nd {
				continue
			}
			commitDist[p] = nd
			queue = append(queue, queueItem{p, nd})
		}
	}
	return include, commitDist
}

// walkHaves returns the objects the client already holds: the full closure
// of the haves, except that the walk never crosses the client's shallow
// boundary — a boundary commit contributes itself and its tree, but not its
// parents, which the client does not hold.
func walkHaves(snap *RepoSnapshot, req fetchRequest) map[string]bool {
	exclude := make(map[string]bool)
	shallowSet := make(map[string]bool, len(req.shallow))
	for _, b := range req.shallow {
		shallowSet[b] = true
	}
	visited := make(map[string]bool)
	stack := append([]string(nil), req.haves...)
	for len(stack) > 0 {
		oid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[oid] {
			continue
		}
		visited[oid] = true
		obj := snap.Objects[oid]
		if obj == nil {
			continue
		}
		exclude[oid] = true
		switch obj.Type {
		case ObjCommit:
			if obj.Commit != nil {
				addTreeClosure(snap, obj.Commit.Tree, exclude)
				if !shallowSet[oid] {
					stack = append(stack, obj.Commit.Parents...)
				}
			}
		case ObjTag:
			if obj.Tag != nil {
				stack = append(stack, obj.Tag.Object)
			}
		case ObjTree:
			addTreeClosure(snap, oid, exclude)
		}
	}
	return exclude
}

// addTreeClosure adds a tree and every object reachable from it to set,
// skipping gitlinks (mode 160000), which name commits the repo does not
// hold. Dangling entries are skipped.
func addTreeClosure(snap *RepoSnapshot, treeOID string, set map[string]bool) {
	stack := []string{treeOID}
	for len(stack) > 0 {
		oid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if set[oid] {
			continue
		}
		obj := snap.Objects[oid]
		if obj == nil || obj.Type != ObjTree {
			continue
		}
		set[oid] = true
		for _, e := range obj.Tree {
			if e.Mode == "160000" {
				continue
			}
			child, ok := snap.Objects[e.SHA]
			if !ok {
				continue
			}
			if child.Type == ObjTree {
				stack = append(stack, e.SHA)
			} else {
				set[e.SHA] = true
			}
		}
	}
}

// fetchV2 answers a v2 fetch: acknowledgments, shallow-info (only when a
// depth was requested and the boundary moved), then the packfile section.
// The packfile section is sideband-framed (band 1): the client requires it
// even though real git sends a raw pack here.
func fetchV2(snap *RepoSnapshot, args []string, buf *[]byte) ([]byte, error) {
	req := parseFetchArgs(args)
	plan, err := planFetch(snap, req)
	if err != nil {
		return nil, err
	}
	out := *buf
	out = appendPktText(out, "acknowledgments\n")
	if len(plan.acks) == 0 {
		out = appendPktText(out, "NAK\n")
	} else {
		for _, ack := range plan.acks {
			out = appendPktText(out, "ACK "+ack+"\n")
		}
	}
	out = appendFlush(out)
	if req.hasDepth && (len(plan.shallow) > 0 || len(plan.unshallow) > 0) {
		out = appendPktText(out, "shallow-info\n")
		for _, oid := range plan.shallow {
			out = appendPktText(out, "shallow "+oid+"\n")
		}
		for _, oid := range plan.unshallow {
			out = appendPktText(out, "unshallow "+oid+"\n")
		}
		out = appendFlush(out)
	}
	out = appendPktText(out, "packfile\n")
	out = appendSideband(out, plan.pack)
	out = appendFlush(out)
	*buf = out
	return *buf, nil
}

// handleV0Fetch answers a v0 fetch: shallow/unshallow lines and the
// ACK/NAK line as plain pkt-lines, then the sideband-framed pack.
func handleV0Fetch(snap *RepoSnapshot, lines []PktLine, buf *[]byte) ([]byte, error) {
	var args []string
	for _, ln := range lines {
		if ln.Flush || ln.Delim || ln.End {
			continue
		}
		args = append(args, strings.TrimSuffix(string(ln.Payload), "\n"))
	}
	req := parseFetchArgs(args)
	plan, err := planFetch(snap, req)
	if err != nil {
		return nil, err
	}
	out := *buf
	for _, oid := range plan.shallow {
		out = appendPktText(out, "shallow "+oid+"\n")
	}
	for _, oid := range plan.unshallow {
		out = appendPktText(out, "unshallow "+oid+"\n")
	}
	if len(plan.acks) == 0 {
		out = appendPktText(out, "NAK\n")
	} else {
		for _, ack := range plan.acks {
			out = appendPktText(out, "ACK "+ack+"\n")
		}
	}
	out = appendSideband(out, plan.pack)
	out = appendFlush(out)
	*buf = out
	return *buf, nil
}

// --- receive-pack ------------------------------------------------------------

// pushCommand is one receive-pack ref update: old and new ids (zero for
// create/delete) and the full ref name.
type pushCommand struct {
	oldSHA string
	newSHA string
	ref    string
}

// refReport is one per-ref report-status outcome.
type refReport struct {
	ref    string
	ok     bool
	reason string
}

func gitHandleReceivePack(w http.ResponseWriter, r *http.Request, repo *Repo, s *Store) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<20))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "cannot read request body")
		return
	}
	cmds, sideband, packBytes, err := parseReceiveBody(body)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "malformed receive-pack stream")
		return
	}
	unpackDetail := "ok"
	reports := make([]refReport, 0, len(cmds))
	if len(packBytes) > 0 {
		objects, perr := ParsePackWithResolver(packBytes, func(oid string) (ObjectType, []byte, bool) {
			if obj, ok := s.GetObject(repo, oid); ok {
				return obj.Type, obj.Raw, true
			}
			return 0, nil, false
		})
		if perr != nil {
			unpackDetail = "error: " + singleLine(perr.Error())
			for _, cmd := range cmds {
				reports = append(reports, refReport{ref: cmd.ref, reason: "unpack failed"})
			}
		} else {
			putUnpackedObjects(s, repo, objects)
		}
	}
	if unpackDetail == "ok" {
		for _, cmd := range cmds {
			if cmd.newSHA != ZeroSHA {
				if _, ok := s.GetObject(repo, cmd.newSHA); !ok {
					reports = append(reports, refReport{ref: cmd.ref, reason: "object not found"})
					continue
				}
			}
			uerr := s.UpdateRefChecked(repo, cmd.ref, cmd.oldSHA, cmd.newSHA)
			switch {
			case uerr == nil:
				reports = append(reports, refReport{ref: cmd.ref, ok: true})
			case errors.Is(uerr, ErrNonFastForward) || errors.Is(uerr, ErrStaleOld):
				reports = append(reports, refReport{ref: cmd.ref, reason: "non-fast-forward"})
			case errors.Is(uerr, ErrRefNotFound):
				reports = append(reports, refReport{ref: cmd.ref, reason: "ref not found"})
			default:
				reports = append(reports, refReport{ref: cmd.ref, reason: singleLine(uerr.Error())})
			}
		}
	}
	buf := takeGitBuf()
	defer releaseGitBuf(buf)
	*buf = buildPushReport(*buf, unpackDetail, reports, sideband)
	gitWriteBinary(w, "application/x-git-receive-pack-result", *buf)
}

// putUnpackedObjects stores freshly unpacked objects through the store's
// batch insert: one lock, precomputed SHAs, no re-hash per object. It is
// the single call site for the batch API.
func putUnpackedObjects(s *Store, r *Repo, objs []*PackObject) {
	s.PutObjectsBatch(r, objs)
}

// singleLine strips line breaks from an error string so it fits on one
// report-status line.
func singleLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// parseReceiveBody splits a receive-pack body into its pkt-line command
// list (up to the flush packet) and the trailing raw pack bytes, and reports
// whether the client negotiated side-band-64k on the first command line.
func parseReceiveBody(body []byte) (cmds []pushCommand, sideband bool, pack []byte, err error) {
	off := 0
	var rawLines []string
	for {
		if off+4 > len(body) {
			return nil, false, nil, errors.New("receive-pack: truncated command list")
		}
		n64, perr := strconv.ParseUint(string(body[off:off+4]), 16, 16)
		if perr != nil {
			return nil, false, nil, errors.New("receive-pack: bad pkt-line length")
		}
		n := int(n64)
		if n == 0 {
			off += 4
			break
		}
		if n < 4 || off+n > len(body) {
			return nil, false, nil, errors.New("receive-pack: pkt-line length out of range")
		}
		rawLines = append(rawLines, string(body[off+4:off+n]))
		off += n
	}
	pack = body[off:]
	var caps []string
	for i, raw := range rawLines {
		line := strings.TrimSuffix(raw, "\n")
		if idx := strings.IndexByte(line, 0); idx >= 0 {
			if i == 0 {
				caps = strings.Fields(line[idx+1:])
			}
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, false, nil, errors.New("receive-pack: bad command line")
		}
		if !isOID(fields[0]) || !isOID(fields[1]) || !strings.HasPrefix(fields[2], "refs/") {
			return nil, false, nil, errors.New("receive-pack: bad command")
		}
		cmds = append(cmds, pushCommand{oldSHA: fields[0], newSHA: fields[1], ref: fields[2]})
	}
	if len(cmds) == 0 {
		return nil, false, nil, errors.New("receive-pack: no commands")
	}
	for _, c := range caps {
		if c == "side-band-64k" {
			sideband = true
		}
	}
	return cmds, sideband, pack, nil
}

// isOID reports whether s is a 40-hex object id.
func isOID(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < 40; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// buildPushReport renders the report-status stream into dst: an unpack line
// plus one ok/ng line per command, pkt-line framed. With sideband
// negotiated the framed stream is carried inside band-1 packets; otherwise
// it is the body.
func buildPushReport(dst []byte, unpackDetail string, reports []refReport, sideband bool) []byte {
	var inner []byte
	inner = appendPktText(inner, "unpack "+unpackDetail+"\n")
	for _, rep := range reports {
		if rep.ok {
			inner = appendPktText(inner, "ok "+rep.ref+"\n")
		} else {
			inner = appendPktText(inner, "ng "+rep.ref+" "+rep.reason+"\n")
		}
	}
	inner = appendFlush(inner)
	if !sideband {
		return append(dst, inner...)
	}
	dst = appendSideband(dst, inner)
	dst = appendFlush(dst)
	return dst
}
