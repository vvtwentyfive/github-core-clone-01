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

package main

import (
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// ParseGitPath splits "/{owner}/{repo}.git/{rest...}" into owner, repo (the
// ".git" suffix stripped), and the rest of the path. It reports false when
// the path is not a git smart-HTTP path.
func ParseGitPath(path string) (owner, repo, rest string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
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

// gitSnapshot is a consistent point-in-time copy of a repo's refs and object
// map, taken under one read lock. GitObjects are immutable once stored, so
// the snapshot stays valid after the lock is released.
type gitSnapshot struct {
	refs     map[string]string
	refNames []string // sorted
	objs     map[string]*GitObject
}

func gitTakeSnapshot(s *Store, r *Repo) gitSnapshot {
	s.RLock()
	defer s.RUnlock()
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
	return gitSnapshot{refs: refs, refNames: names, objs: objs}
}

// peel follows annotated tag objects to their ultimate target (up to 16
// hops). Non-tag ids pass through unchanged.
func (snap gitSnapshot) peel(oid string) string {
	for i := 0; i < 16; i++ {
		obj := snap.objs[oid]
		if obj == nil || obj.Type != ObjTag || obj.Tag == nil {
			return oid
		}
		oid = obj.Tag.Object
	}
	return oid
}

// --- pkt-line output helpers -----------------------------------------------

var gitHexDigits = []byte("0123456789abcdef")

// gitAppendPkt appends one pkt-line framing payload.
func gitAppendPkt(dst, payload []byte) []byte {
	n := len(payload) + 4
	dst = append(dst,
		gitHexDigits[(n>>12)&0xf],
		gitHexDigits[(n>>8)&0xf],
		gitHexDigits[(n>>4)&0xf],
		gitHexDigits[n&0xf],
	)
	return append(dst, payload...)
}

// gitAppendPktString appends one pkt-line framing s.
func gitAppendPktString(dst []byte, s string) []byte {
	return gitAppendPkt(dst, []byte(s))
}

// gitAppendFlush appends a flush packet.
func gitAppendFlush(dst []byte) []byte {
	return append(dst, '0', '0', '0', '0')
}

// gitSidebandChunk is the largest pack-data chunk per sideband packet: the
// 65,520-byte pkt-line limit minus the 4-byte length header and the band byte.
const gitSidebandChunk = 65515

// gitAppendSideband appends data as band-1 sideband packets.
func gitAppendSideband(dst, data []byte) []byte {
	for len(data) > 0 {
		n := len(data)
		if n > gitSidebandChunk {
			n = gitSidebandChunk
		}
		chunk := data[:n]
		data = data[n:]
		total := 4 + 1 + len(chunk)
		dst = append(dst,
			gitHexDigits[(total>>12)&0xf],
			gitHexDigits[(total>>8)&0xf],
			gitHexDigits[(total>>4)&0xf],
			gitHexDigits[total&0xf],
		)
		dst = append(dst, 1)
		dst = append(dst, chunk...)
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
	snap := gitTakeSnapshot(s, repo)
	var body []byte
	var ctype string
	if service == "git-upload-pack" && strings.Contains(r.Header.Get("Git-Protocol"), "version=2") {
		body = gitV2Advertisement()
		ctype = "application/x-git-upload-pack-advertisement"
	} else if service == "git-upload-pack" {
		body = gitV0Advertisement(snap, service, gitUploadPackCaps)
		ctype = "application/x-git-upload-pack-advertisement"
	} else {
		body = gitV0Advertisement(snap, service, gitReceivePackCaps)
		ctype = "application/x-git-receive-pack-advertisement"
	}
	gitWriteBinary(w, ctype, body)
}

// gitV2Advertisement renders the protocol v2 capability advertisement. The
// fetch capability must name shallow (the client refuses shallow fetches
// otherwise). ls-refs is advertised bare: advertising unborn would make the
// client request unborn lines, and an unborn refs/heads/main line would read
// as a real ref on an empty repo.
func gitV2Advertisement() []byte {
	var out []byte
	out = gitAppendPktString(out, "version 2\n")
	out = gitAppendPktString(out, "fetch=shallow\n")
	out = gitAppendPktString(out, "ls-refs\n")
	out = gitAppendPktString(out, "object-format=sha1\n")
	out = gitAppendPktString(out, "agent=forge/1.0\n")
	out = gitAppendFlush(out)
	return out
}

// gitV0Advertisement renders a v0 ref advertisement: the service preamble
// and flush, then HEAD (when the default branch exists), every ref sorted by
// name with peeled tag lines, capabilities on the first line. An empty repo
// advertises only the capabilities^{} pseudo-ref at the zero id.
func gitV0Advertisement(snap gitSnapshot, service, caps string) []byte {
	var out []byte
	out = gitAppendPktString(out, "# service="+service+"\n")
	out = gitAppendFlush(out)
	type refLine struct{ oid, name string }
	var lines []refLine
	if mainTip, ok := snap.refs[BranchRef(DefaultBranch)]; ok {
		lines = append(lines, refLine{mainTip, "HEAD"})
	}
	for _, name := range snap.refNames {
		oid := snap.refs[name]
		lines = append(lines, refLine{oid, name})
		if obj := snap.objs[oid]; obj != nil && obj.Type == ObjTag {
			if peeled := snap.peel(oid); peeled != oid {
				lines = append(lines, refLine{peeled, name + "^{}"})
			}
		}
	}
	if len(lines) == 0 {
		out = gitAppendPktString(out, ZeroSHA+" capabilities^{}\x00"+caps+"\n")
	} else {
		for i, ln := range lines {
			text := ln.oid + " " + ln.name
			if i == 0 {
				text += "\x00" + caps
			}
			out = gitAppendPktString(out, text+"\n")
		}
	}
	out = gitAppendFlush(out)
	return out
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
	snap := gitTakeSnapshot(s, repo)
	var resp []byte
	if isV2 {
		resp, err = gitHandleV2(snap, lines)
	} else {
		resp, err = gitHandleV0Fetch(snap, lines)
	}
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	gitWriteBinary(w, "application/x-git-upload-pack-result", resp)
}

// gitHandleV2 dispatches a v2 request: the command and its arguments are
// split by the delim packet.
func gitHandleV2(snap gitSnapshot, lines []PktLine) ([]byte, error) {
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
		return gitV2LsRefs(snap, args), nil
	case "fetch":
		return gitV2Fetch(snap, args)
	default:
		return nil, errors.New("unknown or missing v2 command")
	}
}

// gitV2LsRefs answers ls-refs: one line per matching ref, "<oid> <name>"
// with symref-target on HEAD and peeled on annotated tags, when requested.
// Prefix filtering is server-side and applies to HEAD too: HEAD is only
// listed when it matches a prefix (or no prefix was given).
func gitV2LsRefs(snap gitSnapshot, args []string) []byte {
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
	var out []byte
	if symrefs && matches("HEAD") {
		if mainTip, ok := snap.refs[BranchRef(DefaultBranch)]; ok {
			out = gitAppendPktString(out, mainTip+" HEAD symref-target:"+BranchRef(DefaultBranch)+"\n")
		} else if unborn {
			out = gitAppendPktString(out, "unborn HEAD symref-target:"+BranchRef(DefaultBranch)+"\n")
		}
	}
	for _, name := range snap.refNames {
		if !matches(name) {
			continue
		}
		oid := snap.refs[name]
		text := oid + " " + name
		if peel {
			if obj := snap.objs[oid]; obj != nil && obj.Type == ObjTag {
				if peeled := snap.peel(oid); peeled != oid {
					text += " peeled:" + peeled
				}
			}
		}
		out = gitAppendPktString(out, text+"\n")
	}
	out = gitAppendFlush(out)
	return out
}

// gitFetchRequest is a parsed fetch negotiation: wants, haves, the client's
// current shallow boundary, and an optional deepen depth.
type gitFetchRequest struct {
	wants    []string
	haves    []string
	shallow  []string
	depth    int
	hasDepth bool
}

// gitParseFetchArgs parses want/have/shallow/deepen lines from either a v2
// argument list or a v0 request body. Negotiation-only lines (thin-pack,
// no-progress, ofs-delta, done, filter, deepen-since, deepen-not) are
// accepted and ignored.
func gitParseFetchArgs(args []string) gitFetchRequest {
	var req gitFetchRequest
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

// gitFetchPlan is the negotiated fetch result: ACKs, the new shallow
// boundary, and boundary commits that stopped being shallow.
type gitFetchPlan struct {
	acks      []string
	shallow   []string
	unshallow []string
}

// gitPlanFetch computes the objects to send and the negotiation outcome. The
// pack holds exactly the objects reachable from the wants (within the deepen
// depth, when given) minus the objects the client already holds.
func gitPlanFetch(snap gitSnapshot, req gitFetchRequest) (gitFetchPlan, []byte, error) {
	var plan gitFetchPlan
	include, commitDist := gitWalkWants(snap, req)
	exclude := gitWalkHaves(snap, req)
	objects := make([]*GitObject, 0, len(include))
	for oid := range include {
		if exclude[oid] {
			continue
		}
		if obj, ok := snap.objs[oid]; ok {
			objects = append(objects, obj)
		}
	}
	// Fixed order: sorted by id, so identical object sets pack identically.
	sort.Slice(objects, func(i, j int) bool { return objects[i].SHA < objects[j].SHA })
	pack, err := BuildPack(objects)
	if err != nil {
		return plan, nil, err
	}
	seen := make(map[string]bool, len(req.haves))
	for _, h := range req.haves {
		if seen[h] {
			continue
		}
		seen[h] = true
		if _, ok := snap.objs[h]; ok {
			plan.acks = append(plan.acks, h)
		}
	}
	if req.hasDepth {
		boundarySet := make(map[string]bool)
		for oid := range commitDist {
			obj := snap.objs[oid]
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
	return plan, pack, nil
}

// gitWalkWants returns the objects reachable from the wants: every included
// object id, plus the generation distance of every included commit (want
// commits at distance 0). Tag wants contribute the tag chain plus the peeled
// target. With a deepen depth, only commits closer than depth generations
// are included; their trees and blobs are always included in full.
func gitWalkWants(snap gitSnapshot, req gitFetchRequest) (map[string]bool, map[string]int) {
	include := make(map[string]bool)
	commitDist := make(map[string]int)
	type queueItem struct {
		oid  string
		dist int
	}
	var queue []queueItem
	for _, want := range req.wants {
		cur := want
		for i := 0; i < 17; i++ {
			obj := snap.objs[cur]
			if obj == nil || obj.Type != ObjTag || obj.Tag == nil {
				break
			}
			include[cur] = true
			cur = obj.Tag.Object
		}
		obj := snap.objs[cur]
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
			gitAddTreeClosure(snap, cur, include)
		case ObjBlob:
			include[cur] = true
		}
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if d, ok := commitDist[it.oid]; !ok || d != it.dist {
			continue
		}
		obj := snap.objs[it.oid]
		if obj == nil || obj.Commit == nil {
			continue
		}
		include[it.oid] = true
		gitAddTreeClosure(snap, obj.Commit.Tree, include)
		if req.hasDepth && it.dist+1 >= req.depth {
			continue
		}
		for _, p := range obj.Commit.Parents {
			if _, ok := snap.objs[p]; !ok {
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

// gitWalkHaves returns the objects the client already holds: the full
// closure of the haves, except that the walk never crosses the client's
// shallow boundary — a boundary commit contributes itself and its tree, but
// not its parents, which the client does not hold.
func gitWalkHaves(snap gitSnapshot, req gitFetchRequest) map[string]bool {
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
		obj := snap.objs[oid]
		if obj == nil {
			continue
		}
		exclude[oid] = true
		switch obj.Type {
		case ObjCommit:
			if obj.Commit != nil {
				gitAddTreeClosure(snap, obj.Commit.Tree, exclude)
				if !shallowSet[oid] {
					stack = append(stack, obj.Commit.Parents...)
				}
			}
		case ObjTag:
			if obj.Tag != nil {
				stack = append(stack, obj.Tag.Object)
			}
		case ObjTree:
			gitAddTreeClosure(snap, oid, exclude)
		}
	}
	return exclude
}

// gitAddTreeClosure adds a tree and every object reachable from it to set,
// skipping gitlinks (mode 160000), which name commits the repo does not hold.
// Dangling entries are skipped.
func gitAddTreeClosure(snap gitSnapshot, treeOID string, set map[string]bool) {
	stack := []string{treeOID}
	for len(stack) > 0 {
		oid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if set[oid] {
			continue
		}
		obj := snap.objs[oid]
		if obj == nil || obj.Type != ObjTree {
			continue
		}
		set[oid] = true
		for _, e := range obj.Tree {
			if e.Mode == "160000" {
				continue
			}
			child, ok := snap.objs[e.SHA]
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

// gitV2Fetch answers a v2 fetch: acknowledgments, shallow-info (only when a
// depth was requested and the boundary moved), then the packfile section.
// The packfile section is sideband-framed (band 1): the client requires it
// even though real git sends a raw pack here.
func gitV2Fetch(snap gitSnapshot, args []string) ([]byte, error) {
	req := gitParseFetchArgs(args)
	plan, pack, err := gitPlanFetch(snap, req)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = gitAppendPktString(out, "acknowledgments\n")
	if len(plan.acks) == 0 {
		out = gitAppendPktString(out, "NAK\n")
	} else {
		for _, ack := range plan.acks {
			out = gitAppendPktString(out, "ACK "+ack+"\n")
		}
	}
	out = gitAppendFlush(out)
	if req.hasDepth && (len(plan.shallow) > 0 || len(plan.unshallow) > 0) {
		out = gitAppendPktString(out, "shallow-info\n")
		for _, oid := range plan.shallow {
			out = gitAppendPktString(out, "shallow "+oid+"\n")
		}
		for _, oid := range plan.unshallow {
			out = gitAppendPktString(out, "unshallow "+oid+"\n")
		}
		out = gitAppendFlush(out)
	}
	out = gitAppendPktString(out, "packfile\n")
	out = gitAppendSideband(out, pack)
	out = gitAppendFlush(out)
	return out, nil
}

// gitHandleV0Fetch answers a v0 fetch: shallow/unshallow lines and the
// ACK/NAK line as plain pkt-lines, then the sideband-framed pack.
func gitHandleV0Fetch(snap gitSnapshot, lines []PktLine) ([]byte, error) {
	var args []string
	for _, ln := range lines {
		if ln.Flush || ln.Delim || ln.End {
			continue
		}
		args = append(args, strings.TrimSuffix(string(ln.Payload), "\n"))
	}
	req := gitParseFetchArgs(args)
	plan, pack, err := gitPlanFetch(snap, req)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, oid := range plan.shallow {
		out = gitAppendPktString(out, "shallow "+oid+"\n")
	}
	for _, oid := range plan.unshallow {
		out = gitAppendPktString(out, "unshallow "+oid+"\n")
	}
	if len(plan.acks) == 0 {
		out = gitAppendPktString(out, "NAK\n")
	} else {
		for _, ack := range plan.acks {
			out = gitAppendPktString(out, "ACK "+ack+"\n")
		}
	}
	out = gitAppendSideband(out, pack)
	out = gitAppendFlush(out)
	return out, nil
}

// --- receive-pack ------------------------------------------------------------

// gitPushCommand is one receive-pack ref update: old and new ids (zero for
// create/delete) and the full ref name.
type gitPushCommand struct {
	oldSHA string
	newSHA string
	ref    string
}

// gitRefReport is one per-ref report-status outcome.
type gitRefReport struct {
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
	cmds, sideband, packBytes, err := gitParseReceiveBody(body)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "malformed receive-pack stream")
		return
	}
	unpackDetail := "ok"
	reports := make([]gitRefReport, 0, len(cmds))
	if len(packBytes) > 0 {
		objects, perr := ParsePackWithResolver(packBytes, func(oid string) (ObjectType, []byte, bool) {
			if obj, ok := s.GetObject(repo, oid); ok {
				return obj.Type, obj.Raw, true
			}
			return 0, nil, false
		})
		if perr != nil {
			unpackDetail = "error: " + gitSingleLine(perr.Error())
			for _, cmd := range cmds {
				reports = append(reports, gitRefReport{ref: cmd.ref, reason: "unpack failed"})
			}
		} else {
			for _, obj := range objects {
				s.PutObject(repo, obj.Type, obj.Raw)
			}
		}
	}
	if unpackDetail == "ok" {
		for _, cmd := range cmds {
			if cmd.newSHA != ZeroSHA {
				if _, ok := s.GetObject(repo, cmd.newSHA); !ok {
					reports = append(reports, gitRefReport{ref: cmd.ref, reason: "object not found"})
					continue
				}
			}
			uerr := s.UpdateRefChecked(repo, cmd.ref, cmd.oldSHA, cmd.newSHA)
			switch {
			case uerr == nil:
				reports = append(reports, gitRefReport{ref: cmd.ref, ok: true})
			case errors.Is(uerr, ErrNonFastForward) || errors.Is(uerr, ErrStaleOld):
				reports = append(reports, gitRefReport{ref: cmd.ref, reason: "non-fast-forward"})
			case errors.Is(uerr, ErrRefNotFound):
				reports = append(reports, gitRefReport{ref: cmd.ref, reason: "ref not found"})
			default:
				reports = append(reports, gitRefReport{ref: cmd.ref, reason: gitSingleLine(uerr.Error())})
			}
		}
	}
	resp := gitBuildPushReport(unpackDetail, reports, sideband)
	gitWriteBinary(w, "application/x-git-receive-pack-result", resp)
}

// gitSingleLine strips line breaks from an error string so it fits on one
// report-status line.
func gitSingleLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// gitParseReceiveBody splits a receive-pack body into its pkt-line command
// list (up to the flush packet) and the trailing raw pack bytes, and reports
// whether the client negotiated side-band-64k on the first command line.
func gitParseReceiveBody(body []byte) (cmds []gitPushCommand, sideband bool, pack []byte, err error) {
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
		if !gitIsOID(fields[0]) || !gitIsOID(fields[1]) || !strings.HasPrefix(fields[2], "refs/") {
			return nil, false, nil, errors.New("receive-pack: bad command")
		}
		cmds = append(cmds, gitPushCommand{oldSHA: fields[0], newSHA: fields[1], ref: fields[2]})
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

// gitIsOID reports whether s is a 40-hex object id.
func gitIsOID(s string) bool {
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

// gitBuildPushReport renders the report-status stream: an unpack line plus
// one ok/ng line per command, pkt-line framed. With sideband negotiated the
// framed stream is carried inside band-1 packets; otherwise it is the body.
func gitBuildPushReport(unpackDetail string, reports []gitRefReport, sideband bool) []byte {
	var inner []byte
	inner = gitAppendPktString(inner, "unpack "+unpackDetail+"\n")
	for _, rep := range reports {
		if rep.ok {
			inner = gitAppendPktString(inner, "ok "+rep.ref+"\n")
		} else {
			inner = gitAppendPktString(inner, "ng "+rep.ref+" "+rep.reason+"\n")
		}
	}
	inner = gitAppendFlush(inner)
	if !sideband {
		return inner
	}
	var out []byte
	out = gitAppendSideband(out, inner)
	out = gitAppendFlush(out)
	return out
}
