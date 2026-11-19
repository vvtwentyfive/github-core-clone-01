package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// zeroOID is the 40-zero object id: an unborn ref value and the delete
// marker in a receive-pack command list.
const zeroOID = "0000000000000000000000000000000000000000"

// forgeAgent is the agent string this forge advertises in its capabilities.
const forgeAgent = "forge/1.0"

var errPktBad = errors.New("bad pkt-line")
var errPktTruncated = errors.New("truncated pkt-line")

// pktChunk is one parsed pkt-line frame: a data payload, or one of the
// control frames (flush 0000, delim 0001, response-end 0002).
type pktChunk struct {
	flush bool
	delim bool
	end   bool
	data  []byte
}

// scanPackets decodes a whole pkt-line stream. It returns the frames in
// order plus the offset just past the first flush packet, or -1 when the
// stream holds no flush. With stopAtFlush it stops right after that first
// flush, leaving the rest of the body untouched: a receive-pack request
// carries its raw pack bytes there.
func scanPackets(body []byte, stopAtFlush bool) ([]pktChunk, int, error) {
	var out []pktChunk
	afterFlush := -1
	pos := 0
	for pos < len(body) {
		if len(body)-pos < 4 {
			return nil, -1, errPktTruncated
		}
		head := string(body[pos : pos+4])
		switch head {
		case "0000":
			if afterFlush < 0 {
				afterFlush = pos + 4
			}
			out = append(out, pktChunk{flush: true})
			pos += 4
			if stopAtFlush {
				return out, afterFlush, nil
			}
		case "0001":
			out = append(out, pktChunk{delim: true})
			pos += 4
		case "0002":
			out = append(out, pktChunk{end: true})
			pos += 4
		default:
			n, err := strconv.ParseUint(head, 16, 32)
			if err != nil || n < 4 || n > 65520 {
				return nil, -1, errPktBad
			}
			if len(body)-pos < int(n) {
				return nil, -1, errPktTruncated
			}
			out = append(out, pktChunk{data: body[pos+4 : pos+int(n)]})
			pos += int(n)
		}
	}
	return out, afterFlush, nil
}

// packetLines pulls the data payloads out of parsed frames as strings with
// the trailing newline stripped, in order. Control frames are dropped.
func packetLines(chunks []pktChunk) []string {
	var lines []string
	for _, c := range chunks {
		if c.data == nil {
			continue
		}
		lines = append(lines, strings.TrimSuffix(string(c.data), "\n"))
	}
	return lines
}

// sortedUnique dedupes a list of ids and returns it in byte order.
func sortedUnique(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// contains reports whether list holds s.
func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// shortErr renders an error as one short line safe to put in a report-status
// unpack line.
func shortErr(err error) string {
	s := strings.SplitN(err.Error(), "\n", 2)[0]
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 100 {
		s = s[:100]
	}
	if s == "" {
		s = "unpack failed"
	}
	return s
}

// packCacheMu guards the one-time lazy creation of a repo's pack cache when
// the store left it nil.
var packCacheMu sync.Mutex

// packCacheFor returns the repo's pack cache, creating it on first use.
func packCacheFor(rp *Repo) *PackCache {
	if rp.packCache != nil {
		return rp.packCache
	}
	packCacheMu.Lock()
	defer packCacheMu.Unlock()
	if rp.packCache == nil {
		rp.packCache = NewPackCache()
	}
	return rp.packCache
}

// frameSideband wraps data in sideband band frames: one band byte plus a
// slice of the data per pkt-line. A frame holds at most 65515 data bytes so
// the whole pkt-line (4 length bytes + band + data) never exceeds the
// client's 65520-byte pkt-line limit.
func frameSideband(band byte, data []byte) []byte {
	var out bytes.Buffer
	for len(data) > 0 {
		n := len(data)
		if n > 65515 {
			n = 65515
		}
		chunk := make([]byte, 0, n+1)
		chunk = append(chunk, band)
		chunk = append(chunk, data[:n]...)
		out.Write(EncodePktLine(chunk))
		data = data[n:]
	}
	return out.Bytes()
}

// emptyPack builds the 32-byte packfile holding zero objects: header plus
// the SHA-1 trailer over it.
func emptyPack() []byte {
	hdr := make([]byte, 12)
	copy(hdr[0:4], "PACK")
	binary.BigEndian.PutUint32(hdr[4:8], 2)
	binary.BigEndian.PutUint32(hdr[8:12], 0)
	sum := sha1.Sum(hdr)
	out := make([]byte, 0, 32)
	out = append(out, hdr...)
	out = append(out, sum[:]...)
	return out
}

// headTip returns the tip of the default branch, refs/heads/main.
func (a *App) headTip(rp *Repo) (string, bool) {
	return a.store.GetRef(rp, "refs/heads/main")
}

// v0Caps is the capability list a v0 advertisement carries on its first ref
// line, for the given service.
func (a *App) v0Caps(service string) string {
	if service == "git-receive-pack" {
		return "symref=HEAD:refs/heads/main report-status side-band-64k delete-refs agent=" + forgeAgent
	}
	return "symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta multi_ack shallow agent=" + forgeAgent
}

// peeledTarget returns the object an annotated tag ref points at, and false
// for anything that is not an annotated tag.
func (a *App) peeledTarget(rp *Repo, ref Ref) (string, bool) {
	obj := a.store.GetObject(rp, ref.OID)
	if obj == nil || obj.Type != "tag" || obj.Tag == nil {
		return "", false
	}
	return obj.Tag.Object, true
}

// v0Advertisement renders a v0 ref advertisement: the service preamble,
// then HEAD first (carrying the capabilities after a NUL), then the refs in
// name order, each annotated tag followed by its peeled line.
func (a *App) v0Advertisement(rp *Repo, service string) []byte {
	var buf bytes.Buffer
	buf.Write(EncodePktLine([]byte("# service=" + service + "\n")))
	buf.Write(EncodeFlush())
	headOID, _ := a.headTip(rp)
	if headOID == "" {
		headOID = zeroOID
	}
	buf.Write(EncodePktLine([]byte(headOID + " HEAD\x00" + a.v0Caps(service) + "\n")))
	for _, ref := range a.store.ListRefs(rp) {
		buf.Write(EncodePktLine([]byte(ref.OID + " " + ref.Name + "\n")))
		if target, ok := a.peeledTarget(rp, ref); ok {
			buf.Write(EncodePktLine([]byte(target + " " + ref.Name + "^{}\n")))
		}
	}
	buf.Write(EncodeFlush())
	return buf.Bytes()
}

// v2Advertisement renders the protocol v2 capability advertisement. The
// fetch capability names shallow and filter support; ls-refs names unborn.
func v2Advertisement() []byte {
	var buf bytes.Buffer
	buf.Write(EncodePktLine([]byte("version 2\n")))
	buf.Write(EncodePktLine([]byte("ls-refs=unborn\n")))
	buf.Write(EncodePktLine([]byte("fetch=shallow filter\n")))
	buf.Write(EncodePktLine([]byte("object-format=sha1\n")))
	buf.Write(EncodePktLine([]byte("agent=" + forgeAgent + "\n")))
	buf.Write(EncodeFlush())
	return buf.Bytes()
}

// handleInfoRefs serves GET /{owner}/{repo}.git/info/refs. Auth first, then
// the owner must be the token login and the repo must exist, both 404
// otherwise. Upload-pack answers v2 when the client asks for it with
// Git-Protocol: version=2; receive-pack is v0 only.
func (a *App) handleInfoRefs(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !a.requireAuth(w, r) {
		return
	}
	if owner != a.token {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	rp := a.store.GetRepo(owner, repo)
	if rp == nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	service := r.URL.Query().Get("service")
	if service != "git-upload-pack" && service != "git-receive-pack" {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	var body []byte
	if service == "git-upload-pack" && r.Header.Get("Git-Protocol") == "version=2" {
		body = v2Advertisement()
	} else {
		body = a.v0Advertisement(rp, service)
	}
	w.Header().Set("Content-Type", "application/x-"+service+"-advertisement")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleUploadPack serves POST /{owner}/{repo}.git/git-upload-pack: v2
// ls-refs / fetch when the client asks for protocol v2, else v0.
func (a *App) handleUploadPack(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !a.requireAuth(w, r) {
		return
	}
	if owner != a.token {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	rp := a.store.GetRepo(owner, repo)
	if rp == nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if r.Header.Get("Git-Protocol") == "version=2" {
		a.uploadPackV2(w, rp, BodyBytes(r))
		return
	}
	a.uploadPackV0(w, rp, BodyBytes(r))
}

// uploadPackV2 dispatches a v2 upload-pack body on its command line.
func (a *App) uploadPackV2(w http.ResponseWriter, rp *Repo, body []byte) {
	chunks, _, err := scanPackets(body, false)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "bad pkt-line")
		return
	}
	lines := packetLines(chunks)
	if len(lines) == 0 {
		WriteError(w, http.StatusBadRequest, "missing command")
		return
	}
	switch lines[0] {
	case "command=ls-refs":
		a.lsRefsV2(w, rp, lines[1:])
	case "command=fetch":
		a.fetchV2(w, rp, lines[1:])
	default:
		WriteError(w, http.StatusBadRequest, "unknown command")
	}
}

// lsRefsV2 answers a v2 ls-refs command: HEAD first, then refs in name
// order, honouring ref-prefix filtering on the server side, peel and
// symrefs arguments, and an unborn HEAD line for a repo with no tip.
func (a *App) lsRefsV2(w http.ResponseWriter, rp *Repo, args []string) {
	peel, symrefs, unborn := false, false, false
	var prefixes []string
	for _, arg := range args {
		switch {
		case arg == "peel":
			peel = true
		case arg == "symrefs":
			symrefs = true
		case arg == "unborn":
			unborn = true
		case strings.HasPrefix(arg, "ref-prefix "):
			prefixes = append(prefixes, arg[len("ref-prefix "):])
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
	var buf bytes.Buffer
	headOID, headOK := a.headTip(rp)
	if matches("HEAD") {
		if headOK {
			line := headOID + " HEAD"
			if symrefs {
				line += " symref-target:refs/heads/main"
			}
			buf.Write(EncodePktLine([]byte(line + "\n")))
		} else if unborn {
			line := "unborn HEAD"
			if symrefs {
				line += " symref-target:refs/heads/main"
			}
			buf.Write(EncodePktLine([]byte(line + "\n")))
		}
	}
	for _, ref := range a.store.ListRefs(rp) {
		if !matches(ref.Name) {
			continue
		}
		line := ref.OID + " " + ref.Name
		if peel {
			if target, ok := a.peeledTarget(rp, ref); ok {
				line += " peeled:" + target
			}
		}
		buf.Write(EncodePktLine([]byte(line + "\n")))
	}
	buf.Write(EncodeFlush())
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// fetchPlan is the result of planning one fetch: which objects to send,
// which commits sit on the new shallow boundary, which old boundaries
// opened up, and which haves the server acknowledges.
type fetchPlan struct {
	wantsSorted []string
	havesSorted []string
	depth       int
	send        []string
	shallow     []string
	unshallow   []string
	acks        []string
}

// collectObjects walks the object graph from roots into out. A commit
// contributes its tree, and its parents only when includeParents is set;
// a commit named in stopAt contributes its tree but never its parents, so
// a shallow boundary's history stays unheld. Tags resolve to their target,
// trees to their entries (gitlinks skipped).
func collectObjects(lookup func(string) *Object, roots []string, out map[string]bool, includeParents bool, stopAt map[string]bool) {
	stack := append([]string(nil), roots...)
	for len(stack) > 0 {
		oid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if out[oid] {
			continue
		}
		obj := lookup(oid)
		if obj == nil {
			continue
		}
		out[oid] = true
		switch obj.Type {
		case "commit":
			if obj.Commit == nil {
				continue
			}
			stack = append(stack, obj.Commit.Tree)
			if includeParents && !stopAt[oid] {
				stack = append(stack, obj.Commit.Parents...)
			}
		case "tag":
			if obj.Tag != nil {
				stack = append(stack, obj.Tag.Object)
			}
		case "tree":
			if obj.Tree == nil {
				continue
			}
			for _, e := range obj.Tree.Entries {
				if e.Mode == "160000" {
					continue
				}
				stack = append(stack, e.OID)
			}
		}
	}
}

// planFetch works out what a fetch must send. Wants walk out by commit
// distance, cut at depth when one is given; anything reachable from a have
// (stopping at the client's shallow boundaries) is already held and is not
// re-sent. Shallow boundaries are the included commits whose parents were
// cut, plus old boundaries that are still boundaries; an old boundary whose
// parent is now included becomes unshallow.
func (a *App) planFetch(snap *RepoSnapshot, wants, haves, shallow []string, depth int) *fetchPlan {
	plan := &fetchPlan{depth: depth}
	plan.wantsSorted = sortedUnique(wants)
	plan.havesSorted = sortedUnique(haves)
	lookup := func(oid string) *Object {
		if snap == nil || snap.Objects == nil {
			return nil
		}
		return snap.Objects[oid]
	}
	shallowSet := make(map[string]bool, len(shallow))
	for _, s := range shallow {
		shallowSet[s] = true
	}
	held := make(map[string]bool)
	collectObjects(lookup, plan.havesSorted, held, true, shallowSet)

	type queued struct {
		oid  string
		dist int
	}
	included := make(map[string]bool)
	var tags []string
	var extras []string
	queue := make([]queued, 0, len(plan.wantsSorted))
	seenCommit := make(map[string]bool)
	for _, w := range plan.wantsSorted {
		obj := lookup(w)
		if obj == nil {
			continue
		}
		switch obj.Type {
		case "tag":
			tags = append(tags, w)
			if obj.Tag == nil {
				continue
			}
			target := lookup(obj.Tag.Object)
			if target == nil {
				continue
			}
			if target.Type == "commit" {
				queue = append(queue, queued{obj.Tag.Object, 0})
			} else {
				extras = append(extras, obj.Tag.Object)
			}
		case "commit":
			queue = append(queue, queued{w, 0})
		default:
			extras = append(extras, w)
		}
	}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if seenCommit[item.oid] {
			continue
		}
		seenCommit[item.oid] = true
		if depth >= 0 && item.dist >= depth {
			continue
		}
		obj := lookup(item.oid)
		if obj == nil || obj.Type != "commit" || obj.Commit == nil {
			continue
		}
		included[item.oid] = true
		for _, p := range obj.Commit.Parents {
			queue = append(queue, queued{p, item.dist + 1})
		}
	}
	sendSet := make(map[string]bool)
	roots := make([]string, 0, len(included)+len(tags)+len(extras))
	for oid := range included {
		roots = append(roots, oid)
	}
	roots = append(roots, tags...)
	roots = append(roots, extras...)
	collectObjects(lookup, roots, sendSet, false, nil)
	for oid := range held {
		delete(sendSet, oid)
	}
	for oid := range sendSet {
		plan.send = append(plan.send, oid)
	}
	sort.Strings(plan.send)
	if depth >= 0 {
		for oid := range included {
			obj := lookup(oid)
			if obj == nil || obj.Commit == nil || len(obj.Commit.Parents) == 0 {
				continue
			}
			cut := true
			for _, p := range obj.Commit.Parents {
				if included[p] {
					cut = false
					break
				}
			}
			if cut {
				plan.shallow = append(plan.shallow, oid)
			}
		}
		for _, b := range shallow {
			obj := lookup(b)
			if obj == nil || obj.Type != "commit" || obj.Commit == nil {
				continue
			}
			moved := false
			for _, p := range obj.Commit.Parents {
				if included[p] {
					moved = true
					break
				}
			}
			if moved {
				plan.unshallow = append(plan.unshallow, b)
			} else if (held[b] || included[b]) && !contains(plan.shallow, b) {
				plan.shallow = append(plan.shallow, b)
			}
		}
		sort.Strings(plan.shallow)
		sort.Strings(plan.unshallow)
	}
	if len(plan.havesSorted) > 0 {
		ancestors := make(map[string]bool)
		collectObjects(lookup, plan.wantsSorted, ancestors, true, nil)
		for _, h := range plan.havesSorted {
			if ancestors[h] {
				plan.acks = append(plan.acks, h)
			}
		}
	}
	return plan
}

// packFor returns the packfile for a fetch plan: an empty pack when nothing
// is to be sent, else the pack-cache entry for this generation + wants +
// haves + depth, built cold from the snapshot on a miss.
func (a *App) packFor(rp *Repo, snap *RepoSnapshot, plan *fetchPlan) ([]byte, error) {
	if len(plan.send) == 0 {
		return emptyPack(), nil
	}
	depth := plan.depth
	if depth < 0 {
		depth = 0
	}
	key := PackCacheKey{
		Generation: snap.Generation,
		Wants:      strings.Join(plan.wantsSorted, ","),
		Haves:      strings.Join(plan.havesSorted, ","),
		Depth:      depth,
	}
	return packCacheFor(rp).GetOrBuild(key, func() ([]byte, error) {
		return BuildPack(snap, plan.send)
	})
}

// fetchV2 answers a v2 fetch command: acknowledgments, then shallow-info
// when a depth was requested, then the packfile section with the pack in
// sideband-64k framing.
func (a *App) fetchV2(w http.ResponseWriter, rp *Repo, args []string) {
	var wants, haves, shallow []string
	depth := -1
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "want "):
			wants = append(wants, strings.TrimSpace(arg[len("want "):]))
		case strings.HasPrefix(arg, "have "):
			haves = append(haves, strings.TrimSpace(arg[len("have "):]))
		case strings.HasPrefix(arg, "shallow "):
			shallow = append(shallow, strings.TrimSpace(arg[len("shallow "):]))
		case strings.HasPrefix(arg, "deepen "):
			if n, err := strconv.Atoi(strings.TrimSpace(arg[len("deepen "):])); err == nil {
				depth = n
			}
		}
	}
	snap := a.store.Snapshot(rp)
	if snap == nil {
		WriteError(w, http.StatusInternalServerError, "no snapshot")
		return
	}
	plan := a.planFetch(snap, wants, haves, shallow, depth)
	pack, err := a.packFor(rp, snap, plan)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "pack failed")
		return
	}
	var buf bytes.Buffer
	buf.Write(EncodePktLine([]byte("acknowledgments\n")))
	if len(plan.acks) == 0 {
		buf.Write(EncodePktLine([]byte("NAK\n")))
	} else {
		for _, ack := range plan.acks {
			buf.Write(EncodePktLine([]byte("ACK " + ack + "\n")))
		}
		buf.Write(EncodePktLine([]byte("ready\n")))
	}
	buf.Write([]byte("0001"))
	if len(plan.shallow) > 0 || len(plan.unshallow) > 0 {
		buf.Write(EncodePktLine([]byte("shallow-info\n")))
		for _, s := range plan.shallow {
			buf.Write(EncodePktLine([]byte("shallow " + s + "\n")))
		}
		for _, s := range plan.unshallow {
			buf.Write(EncodePktLine([]byte("unshallow " + s + "\n")))
		}
		buf.Write([]byte("0001"))
	}
	buf.Write(EncodePktLine([]byte("packfile\n")))
	buf.Write(frameSideband(1, pack))
	buf.Write(EncodeFlush())
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// uploadPackV0 answers a v0 upload-pack body: wants and deepen in the first
// section, haves and done in the second. The reply is NAK or ACK lines,
// shallow/unshallow lines, then the pack in sideband framing.
func (a *App) uploadPackV0(w http.ResponseWriter, rp *Repo, body []byte) {
	chunks, _, err := scanPackets(body, false)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "bad pkt-line")
		return
	}
	var sections [][]string
	var cur []string
	for _, c := range chunks {
		if c.flush {
			sections = append(sections, cur)
			cur = nil
			continue
		}
		if c.data == nil {
			continue
		}
		cur = append(cur, strings.TrimSuffix(string(c.data), "\n"))
	}
	if len(cur) > 0 {
		sections = append(sections, cur)
	}
	var wants, haves, shallow []string
	depth := -1
	if len(sections) > 0 {
		for _, line := range sections[0] {
			switch {
			case strings.HasPrefix(line, "want "):
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					wants = append(wants, fields[1])
				}
			case strings.HasPrefix(line, "shallow "):
				shallow = append(shallow, strings.TrimSpace(line[len("shallow "):]))
			case strings.HasPrefix(line, "deepen "):
				if n, err := strconv.Atoi(strings.TrimSpace(line[len("deepen "):])); err == nil {
					depth = n
				}
			}
		}
	}
	if len(sections) > 1 {
		for _, line := range sections[1] {
			if strings.HasPrefix(line, "have ") {
				haves = append(haves, strings.TrimSpace(line[len("have "):]))
			}
		}
	}
	snap := a.store.Snapshot(rp)
	if snap == nil {
		WriteError(w, http.StatusInternalServerError, "no snapshot")
		return
	}
	plan := a.planFetch(snap, wants, haves, shallow, depth)
	pack, err := a.packFor(rp, snap, plan)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "pack failed")
		return
	}
	var buf bytes.Buffer
	if len(plan.acks) == 0 {
		buf.Write(EncodePktLine([]byte("NAK\n")))
	} else {
		for _, ack := range plan.acks {
			buf.Write(EncodePktLine([]byte("ACK " + ack + "\n")))
		}
	}
	for _, s := range plan.shallow {
		buf.Write(EncodePktLine([]byte("shallow " + s + "\n")))
	}
	for _, s := range plan.unshallow {
		buf.Write(EncodePktLine([]byte("unshallow " + s + "\n")))
	}
	buf.Write(frameSideband(1, pack))
	buf.Write(EncodeFlush())
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// pushCommand is one line of a receive-pack command list.
type pushCommand struct {
	old string
	new string
	ref string
}

// handleReceivePack serves POST /{owner}/{repo}.git/git-receive-pack (v0
// only). It parses the command list, unpacks the pack that follows the
// flush, stores the objects in one batch, then applies each ref update
// fast-forward and answers report-status: unpack ok plus one ok/ng line
// per ref, framed in sideband band 1 when the client asked for it. A
// refused ref never moves, but an accepted ref in the same list does.
func (a *App) handleReceivePack(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if !a.requireAuth(w, r) {
		return
	}
	if owner != a.token {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	rp := a.store.GetRepo(owner, repo)
	if rp == nil {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	body := BodyBytes(r)
	chunks, afterFlush, err := scanPackets(body, true)
	if err != nil || afterFlush < 0 {
		WriteError(w, http.StatusBadRequest, "bad pkt-line")
		return
	}
	var cmds []pushCommand
	sideband := false
	firstData := true
	for _, c := range chunks {
		if c.data == nil {
			continue
		}
		line := strings.TrimSuffix(string(c.data), "\n")
		if firstData {
			firstData = false
			if nul := strings.IndexByte(line, 0); nul >= 0 {
				for _, tok := range strings.Fields(line[nul+1:]) {
					if tok == "side-band-64k" {
						sideband = true
					}
				}
				line = line[:nul]
			}
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			WriteError(w, http.StatusBadRequest, "bad command")
			return
		}
		cmds = append(cmds, pushCommand{old: parts[0], new: parts[1], ref: parts[2]})
	}
	pack := body[afterFlush:]
	unpackOK := true
	unpackErr := ""
	var objs []RawObject
	if len(pack) > 0 {
		var perr error
		objs, perr = ParsePack(pack)
		if perr != nil {
			unpackOK = false
			unpackErr = shortErr(perr)
		}
	} else {
		for _, cmd := range cmds {
			if cmd.new != zeroOID {
				unpackOK = false
				unpackErr = "missing pack"
				break
			}
		}
	}
	if unpackOK && len(objs) > 0 {
		a.store.PutObjectsBatch(rp, objs)
	}
	var report bytes.Buffer
	if unpackOK {
		report.Write(EncodePktLine([]byte("unpack ok\n")))
	} else {
		report.Write(EncodePktLine([]byte("unpack " + unpackErr + "\n")))
	}
	for _, cmd := range cmds {
		if !unpackOK {
			report.Write(EncodePktLine([]byte("ng " + cmd.ref + " unpack failed\n")))
			continue
		}
		oldArg := cmd.old
		if oldArg == zeroOID {
			oldArg = ""
		}
		if err := a.store.UpdateRefChecked(rp, cmd.ref, oldArg, cmd.new); err != nil {
			report.Write(EncodePktLine([]byte("ng " + cmd.ref + " non-fast-forward\n")))
		} else {
			report.Write(EncodePktLine([]byte("ok " + cmd.ref + "\n")))
		}
	}
	report.Write(EncodeFlush())
	var out bytes.Buffer
	if sideband {
		out.Write(frameSideband(1, report.Bytes()))
	} else {
		out.Write(report.Bytes())
	}
	out.Write(EncodeFlush())
	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.Bytes())
}
