// Pkt-line framing and packfile codec for the git protocol.
//
// The pkt-line helpers frame the smart-HTTP streams. BuildPack assembles
// version-2 packfiles from whole objects (no deltas are written); ParsePack
// decodes packfiles with full OFS_DELTA and REF_DELTA resolution, including
// delta chains, and verifies the trailer checksum. ParsePackWithResolver
// additionally resolves thin-pack REF_DELTA bases already held in the store.
//
// Performance shape (v2): zlib writers and readers are pooled (a fresh
// compressor/decompressor per entry costs Huffman-table setup every time);
// BuildPack's SHA-1 trailer is computed once over the finished bytes; and
// PackCache memoizes built pack bytes keyed by (repo generation + wants +
// haves + depth) with single-flight builds, so concurrent clones of the
// same repo at the same generation share one build. The generation in the
// key is the invalidation: any push bumps it and old entries simply never
// match again.

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// PktFlushBytes is the flush packet ("0000").
var PktFlushBytes = []byte("0000")

// PktDelimBytes is the delimiter packet ("0001").
var PktDelimBytes = []byte("0001")

var pktHexDigits = []byte("0123456789abcdef")

// appendPktLen appends a 4-hex-digit length (including the 4 length bytes).
func appendPktLen(dst []byte, n int) []byte {
	return append(dst,
		pktHexDigits[(n>>12)&0xf],
		pktHexDigits[(n>>8)&0xf],
		pktHexDigits[(n>>4)&0xf],
		pktHexDigits[n&0xf],
	)
}

// EncodePktLine frames payload as one pkt-line: a 4-hex-digit length
// (including the 4 length bytes) followed by the payload.
func EncodePktLine(payload []byte) ([]byte, error) {
	n := len(payload) + 4
	if n > 0xffff {
		return nil, fmt.Errorf("pkt-line too large: %d bytes", len(payload))
	}
	out := make([]byte, 0, n)
	out = appendPktLen(out, n)
	return append(out, payload...), nil
}

// EncodePktLineString frames s as one pkt-line.
func EncodePktLineString(s string) ([]byte, error) {
	return EncodePktLine([]byte(s))
}

// PktLine is one decoded pkt-line: a flush, delimiter, or response-end
// marker, or a payload packet.
type PktLine struct {
	Flush   bool
	Delim   bool
	End     bool
	Payload []byte
}

// DecodePktLines decodes a pkt-line stream. Payload slices alias data.
// The 4-hex-digit length is parsed by hand so decoding allocates nothing
// per line.
func DecodePktLines(data []byte) ([]PktLine, error) {
	var lines []PktLine
	for off := 0; off < len(data); {
		if len(data)-off < 4 {
			return nil, errors.New("pkt-line: truncated length prefix")
		}
		n := 0
		valid := true
		for _, c := range data[off : off+4] {
			var v int
			switch {
			case c >= '0' && c <= '9':
				v = int(c - '0')
			case c >= 'a' && c <= 'f':
				v = int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v = int(c-'A') + 10
			default:
				valid = false
			}
			n = n*16 + v
		}
		if !valid {
			return nil, fmt.Errorf("pkt-line: bad length %q", string(data[off:off+4]))
		}
		switch n {
		case 0:
			lines = append(lines, PktLine{Flush: true})
			off += 4
		case 1:
			lines = append(lines, PktLine{Delim: true})
			off += 4
		case 2:
			lines = append(lines, PktLine{End: true})
			off += 4
		default:
			if n < 4 || off+n > len(data) {
				return nil, fmt.Errorf("pkt-line: length %d out of range", n)
			}
			lines = append(lines, PktLine{Payload: data[off+4 : off+n]})
			off += n
		}
	}
	return lines, nil
}

// PackObject is one object decoded from a packfile.
type PackObject struct {
	Type ObjectType
	Raw  []byte
	SHA  string
}

// gitPackMaxObjectSize caps one inflated object (or one delta result) so a
// corrupt pack cannot force an unbounded allocation.
const gitPackMaxObjectSize = 64 << 20

// Pack type codes, indexed both ways by table instead of switch: commit 1,
// tree 2, blob 3, tag 4. ObjectType values are blob 1, tree 2, commit 3,
// tag 4, so the forward table is keyed by ObjectType.
var packCodeByType = [...]int{0, 3, 2, 1, 4}
var packTypeByCode = [...]ObjectType{0, ObjCommit, ObjTree, ObjBlob, ObjTag}

// gitPackTypeCode maps an object type to its pack type code.
func gitPackTypeCode(t ObjectType) (int, bool) {
	if t < 1 || int(t) > 4 {
		return 0, false
	}
	return packCodeByType[t], true
}

// gitPackTypeFromCode maps a pack type code back to an object type.
func gitPackTypeFromCode(code int) (ObjectType, bool) {
	if code < 1 || code > 4 {
		return 0, false
	}
	return packTypeByCode[code], true
}

// gitPackAppendHeader appends a pack entry header: the type in bits 4-6 of
// the first byte, the low 4 bits of the size in bits 0-3, then the remaining
// size in 7-bit little-endian groups with the continuation bit set on all
// but the last byte.
func gitPackAppendHeader(dst []byte, typeCode, size int) []byte {
	first := byte(typeCode<<4) | byte(size&0x0f)
	size >>= 4
	for size > 0 {
		dst = append(dst, first|0x80)
		first = byte(size & 0x7f)
		size >>= 7
	}
	return append(dst, first)
}

// Pooled zlib writers: a compressor's tables are expensive to build, so
// BuildPack reuses one writer per pack and resets it per object instead of
// allocating a fresh writer for every entry.
var pooledZlibWriters = sync.Pool{
	New: func() any { return zlib.NewWriter(io.Discard) },
}

// BuildPack assembles a version-2 packfile holding the given objects, in the
// given order, as whole objects (no deltas). The output is deterministic for
// identical inputs: same order, same compression level, trailer SHA-1 over
// all preceding bytes, computed once.
func BuildPack(objects []*GitObject) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(12 + len(objects)*64)
	var head [12]byte
	copy(head[0:4], "PACK")
	binary.BigEndian.PutUint32(head[4:8], 2)
	binary.BigEndian.PutUint32(head[8:12], uint32(len(objects)))
	buf.Write(head[:])
	zw := pooledZlibWriters.Get().(*zlib.Writer)
	defer pooledZlibWriters.Put(zw)
	for _, obj := range objects {
		if obj == nil {
			return nil, errors.New("pack: nil object")
		}
		code, ok := gitPackTypeCode(obj.Type)
		if !ok {
			return nil, fmt.Errorf("pack: unknown object type %v", obj.Type)
		}
		var hb [10]byte
		buf.Write(gitPackAppendHeader(hb[:0], code, len(obj.Raw)))
		zw.Reset(&buf)
		if _, err := zw.Write(obj.Raw); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
	}
	sum := sha1.Sum(buf.Bytes())
	buf.Write(sum[:])
	return buf.Bytes(), nil
}

// PackCacheKey identifies one built pack: the repo generation it was built
// at, the sorted want and have ids, and the deepen depth (0 when no deepen
// was requested). Two fetches with the same key hold the same objects, so
// they pack to identical bytes.
type PackCacheKey struct {
	Generation uint64
	Wants      string // "\n"-joined sorted want ids
	Haves      string // "\n"-joined sorted have ids
	Depth      int    // 0 when no deepen was requested
}

// PackCacheKeyFor builds a PackCacheKey from a generation and raw want/have
// lists; the lists are sorted and deduplicated, so argument order does not
// matter.
func PackCacheKeyFor(generation uint64, wants, haves []string, depth int) PackCacheKey {
	return PackCacheKey{
		Generation: generation,
		Wants:      joinSortedIDs(wants),
		Haves:      joinSortedIDs(haves),
		Depth:      depth,
	}
}

// joinSortedIDs sorts and deduplicates ids, then joins them with "\n".
// An empty list joins to "".
func joinSortedIDs(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	out := sorted[:1]
	for _, id := range sorted[1:] {
		if id != out[len(out)-1] {
			out = append(out, id)
		}
	}
	return strings.Join(out, "\n")
}

// packCacheEntry is one cached pack build; done closes when the build
// finishes, so concurrent waiters share a single in-flight build.
type packCacheEntry struct {
	done chan struct{}
	pack []byte
	err  error
}

// PackCache memoizes built pack bytes. Entries are keyed by generation, so
// a repo change invalidates them implicitly: a fetch at a new generation
// can never match an entry built at an old one. DropGeneration removes
// stale entries to bound memory; correctness never depends on it.
type PackCache struct {
	mu      sync.Mutex
	entries map[PackCacheKey]*packCacheEntry
}

// NewPackCache creates an empty pack cache.
func NewPackCache() *PackCache {
	return &PackCache{entries: make(map[PackCacheKey]*packCacheEntry)}
}

// packCacheMaxEntries caps the cache; past it the map is reset rather than
// grown without bound (packs are rebuilt deterministically, so dropping
// entries only costs a rebuild).
const packCacheMaxEntries = 512

// Get returns cached pack bytes for key, if a build for it has finished
// successfully. It never blocks on an in-flight build.
func (c *PackCache) Get(key PackCacheKey) ([]byte, bool) {
	c.mu.Lock()
	e, ok := c.entries[key]
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	select {
	case <-e.done:
		if e.err != nil {
			return nil, false
		}
		return e.pack, true
	default:
		return nil, false
	}
}

// pruneLocked drops finished entries when the cache is at capacity, so a
// burst of generations never evicts a build still in flight. Only when
// every entry is still building does it reset the map; a dropped in-flight
// entry is benign (its waiters already hold it, and the key rebuilds
// deterministically). Callers hold c.mu.
func (c *PackCache) pruneLocked() {
	if len(c.entries) < packCacheMaxEntries {
		return
	}
	for k, e := range c.entries {
		select {
		case <-e.done:
			delete(c.entries, k)
		default:
		}
	}
	if len(c.entries) >= packCacheMaxEntries {
		c.entries = make(map[PackCacheKey]*packCacheEntry, packCacheMaxEntries)
	}
}

// Clear drops every cached pack.
func (c *PackCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[PackCacheKey]*packCacheEntry, packCacheMaxEntries)
}

// Put stores finished pack bytes under key.
func (c *PackCache) Put(key PackCacheKey, pack []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked()
	e := &packCacheEntry{done: make(chan struct{}), pack: pack}
	close(e.done)
	c.entries[key] = e
}

// GetOrBuild returns the cached pack for key, or builds it once with build
// and caches the result. Concurrent callers for the same key share the one
// build: the first builds while the rest wait. A failed build is not
// cached, so a later call retries.
func (c *PackCache) GetOrBuild(key PackCacheKey, build func() ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		c.mu.Unlock()
		<-e.done
		return e.pack, e.err
	}
	c.pruneLocked()
	e := &packCacheEntry{done: make(chan struct{})}
	c.entries[key] = e
	c.mu.Unlock()
	pack, err := build()
	e.pack, e.err = pack, err
	close(e.done)
	if err != nil {
		c.mu.Lock()
		if cur, ok := c.entries[key]; ok && cur == e {
			delete(c.entries, key)
		}
		c.mu.Unlock()
	}
	return pack, err
}

// DropGeneration removes every entry built at generation gen (stale after
// the repo moved on). Entries for other generations are untouched.
func (c *PackCache) DropGeneration(gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if k.Generation == gen {
			delete(c.entries, k)
		}
	}
}

// PackBaseResolver supplies a base object held outside the pack (a thin
// pack's REF_DELTA base). It reports false when the object is not held.
type PackBaseResolver func(oid string) (ObjectType, []byte, bool)

// ParsePack decodes a packfile into objects, resolving every delta whose
// base is in the pack. It verifies the trailer checksum and rejects corrupt
// packs.
func ParsePack(data []byte) ([]*PackObject, error) {
	return gitParsePack(data, nil)
}

// ParsePackWithResolver decodes a packfile like ParsePack, consulting
// resolve for REF_DELTA bases that are not in the pack.
func ParsePackWithResolver(data []byte, resolve PackBaseResolver) ([]*PackObject, error) {
	return gitParsePack(data, resolve)
}

// Pooled zlib readers: a decompressor's tables are expensive to build, so
// entry inflation reuses readers from the pool and resets them onto each
// entry's byte stream instead of allocating a fresh reader per entry.
var pooledZlibReaders sync.Pool // holds io.ReadCloser

// zlibResetter is the Reset method every zlib reader carries.
type zlibResetter interface {
	Reset(io.Reader, []byte) error
}

// acquireZlibReader returns a reader over br, reusing a pooled one when
// possible and allocating a fresh one otherwise.
func acquireZlibReader(br *bytes.Reader) (io.ReadCloser, error) {
	if v := pooledZlibReaders.Get(); v != nil {
		zr := v.(io.ReadCloser)
		if rz, ok := zr.(zlibResetter); ok {
			if err := rz.Reset(br, nil); err == nil {
				return zr, nil
			}
		}
	}
	return zlib.NewReader(br)
}

// releaseZlibReader returns a reader to the pool for reuse by a later
// entry. No Close is needed: Reset on the next acquisition discards the
// old stream state, and the reader holds no OS resource.
func releaseZlibReader(zr io.ReadCloser) {
	pooledZlibReaders.Put(zr)
}

// gitPackEntry is one raw pack entry before delta resolution.
type gitPackEntry struct {
	offset     int
	typeCode   int
	size       int
	data       []byte // inflated bytes: object bytes, or delta instructions
	baseOffset int    // ofs-delta only, -1 otherwise
	baseOID    string // ref-delta only
	resolved   bool
	resType    ObjectType
	resRaw     []byte
	resSHA     string
}

func gitParsePack(data []byte, resolve PackBaseResolver) ([]*PackObject, error) {
	if len(data) < 32 {
		return nil, errors.New("pack: too short")
	}
	trailerStart := len(data) - 20
	sum := sha1.Sum(data[:trailerStart])
	if !bytes.Equal(sum[:], data[trailerStart:]) {
		return nil, errors.New("pack: trailer checksum mismatch")
	}
	if string(data[0:4]) != "PACK" {
		return nil, errors.New("pack: bad magic")
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("pack: unsupported version %d", version)
	}
	count := binary.BigEndian.Uint32(data[8:12])
	if count > 1<<24 {
		return nil, errors.New("pack: object count implausible")
	}
	capHint := count
	if capHint > 4096 {
		capHint = 4096
	}
	entries := make([]*gitPackEntry, 0, capHint)
	byOffset := make(map[int]*gitPackEntry, capHint)
	offset := 12
	for i := uint32(0); i < count; i++ {
		entryOffset := offset
		if offset >= trailerStart {
			return nil, errors.New("pack: truncated entry header")
		}
		b := data[offset]
		offset++
		typeCode := int(b>>4) & 0x07
		size := int(b & 0x0f)
		shift := uint(4)
		for b&0x80 != 0 {
			if offset >= trailerStart {
				return nil, errors.New("pack: truncated size varint")
			}
			b = data[offset]
			offset++
			size |= int(b&0x7f) << shift
			shift += 7
			if shift > 63 {
				return nil, errors.New("pack: size varint too long")
			}
		}
		if size < 0 || size > gitPackMaxObjectSize {
			return nil, errors.New("pack: object size out of range")
		}
		entry := &gitPackEntry{offset: entryOffset, typeCode: typeCode, size: size, baseOffset: -1}
		switch typeCode {
		case 1, 2, 3, 4:
		case 6: // ofs-delta: base offset encoded as a backwards varint
			if offset >= trailerStart {
				return nil, errors.New("pack: truncated ofs-delta base")
			}
			b = data[offset]
			offset++
			value := int64(b & 0x7f)
			for b&0x80 != 0 {
				if offset >= trailerStart {
					return nil, errors.New("pack: truncated ofs-delta base")
				}
				b = data[offset]
				offset++
				value = ((value + 1) << 7) | int64(b&0x7f)
				if value > int64(entryOffset) {
					return nil, errors.New("pack: ofs-delta base before pack start")
				}
			}
			if value <= 0 {
				return nil, errors.New("pack: ofs-delta base offset is zero")
			}
			entry.baseOffset = entryOffset - int(value)
		case 7: // ref-delta: 20-byte base object id
			if offset+20 > trailerStart {
				return nil, errors.New("pack: truncated ref-delta base")
			}
			entry.baseOID = hex.EncodeToString(data[offset : offset+20])
			offset += 20
		default:
			return nil, fmt.Errorf("pack: unknown entry type code %d", typeCode)
		}
		// Inflate exactly one zlib stream into a buffer sized to the
		// declared size. bytes.Reader is an io.ByteReader, so the pooled
		// reader consumes exactly the stream's bytes and the reader's
		// remaining length gives the next entry's offset.
		br := bytes.NewReader(data[offset:trailerStart])
		zr, err := acquireZlibReader(br)
		if err != nil {
			return nil, fmt.Errorf("pack: zlib stream at %d: %w", offset, err)
		}
		inflated := make([]byte, size)
		got, rerr := io.ReadFull(zr, inflated)
		if rerr != nil {
			releaseZlibReader(zr)
			if got < size {
				return nil, fmt.Errorf("pack: entry at %d declares %d bytes, inflated %d", entryOffset, size, got)
			}
			return nil, fmt.Errorf("pack: inflate at %d: %w", offset, rerr)
		}
		var extra [1]byte
		if m, _ := zr.Read(extra[:]); m > 0 {
			releaseZlibReader(zr)
			return nil, fmt.Errorf("pack: entry at %d declares %d bytes, inflated more", entryOffset, size)
		}
		releaseZlibReader(zr)
		offset += (trailerStart - offset) - br.Len()
		entry.data = inflated
		entries = append(entries, entry)
		byOffset[entryOffset] = entry
	}
	if offset != trailerStart {
		return nil, errors.New("pack: trailing bytes before trailer")
	}

	// Resolve: whole objects first, then deltas in passes until every entry
	// resolves or a full pass makes no progress (missing base or cycle).
	// Bases may appear after their deltas in the pack, so resolution cannot
	// assume pack order.
	resolvedByOID := make(map[string]*gitPackEntry, len(entries))
	remaining := 0
	for _, e := range entries {
		if e.typeCode >= 1 && e.typeCode <= 4 {
			t, _ := gitPackTypeFromCode(e.typeCode)
			e.resType = t
			e.resRaw = e.data
			e.resSHA = ObjectSHA(t, e.data)
			e.resolved = true
			resolvedByOID[e.resSHA] = e
		} else {
			remaining++
		}
	}
	for remaining > 0 {
		progress := false
		for _, e := range entries {
			if e.resolved {
				continue
			}
			var baseType ObjectType
			var baseRaw []byte
			ok := false
			if e.typeCode == 6 {
				base := byOffset[e.baseOffset]
				if base == nil {
					return nil, fmt.Errorf("pack: ofs-delta at %d names unknown base offset %d", e.offset, e.baseOffset)
				}
				if !base.resolved {
					continue
				}
				baseType, baseRaw, ok = base.resType, base.resRaw, true
			} else {
				if base, found := resolvedByOID[e.baseOID]; found && base.resolved {
					baseType, baseRaw, ok = base.resType, base.resRaw, true
				} else if resolve != nil {
					if t, raw, found := resolve(e.baseOID); found {
						baseType, baseRaw, ok = t, raw, true
					}
				}
				if !ok {
					continue
				}
			}
			raw, err := gitApplyDelta(baseRaw, e.data)
			if err != nil {
				return nil, fmt.Errorf("pack: delta at %d: %w", e.offset, err)
			}
			e.resType = baseType
			e.resRaw = raw
			e.resSHA = ObjectSHA(baseType, raw)
			e.resolved = true
			resolvedByOID[e.resSHA] = e
			remaining--
			progress = true
		}
		if !progress {
			return nil, errors.New("pack: delta base missing or delta cycle")
		}
	}
	out := make([]*PackObject, len(entries))
	for i, e := range entries {
		out[i] = &PackObject{Type: e.resType, Raw: e.resRaw, SHA: e.resSHA}
	}
	return out, nil
}

// gitApplyDelta applies a git delta instruction stream to a base object's
// bytes: two size varints (source, target), then copy/insert opcodes. Copy
// opcodes (high bit set) name offset/size bytes with bits 0-2/4-6; a zero
// copy size means 0x10000; insert opcodes (high bit clear, non-zero) carry
// that many literal bytes; opcode 0 is invalid.
func gitApplyDelta(base, delta []byte) ([]byte, error) {
	off := 0
	readSize := func() (int, error) {
		value := 0
		shift := uint(0)
		for {
			if off >= len(delta) {
				return 0, errors.New("delta: truncated size")
			}
			b := delta[off]
			off++
			value |= int(b&0x7f) << shift
			shift += 7
			if b&0x80 == 0 {
				break
			}
			if shift > 63 {
				return 0, errors.New("delta: size varint too long")
			}
		}
		return value, nil
	}
	srcSize, err := readSize()
	if err != nil {
		return nil, err
	}
	tgtSize, err := readSize()
	if err != nil {
		return nil, err
	}
	if srcSize != len(base) {
		return nil, fmt.Errorf("delta: base size %d, expected %d", len(base), srcSize)
	}
	if tgtSize < 0 || tgtSize > gitPackMaxObjectSize {
		return nil, errors.New("delta: target size out of range")
	}
	out := make([]byte, 0, tgtSize)
	for off < len(delta) {
		op := delta[off]
		off++
		if op&0x80 != 0 {
			copyOff := 0
			copySize := 0
			shift := uint(0)
			for bit := uint(0); bit < 4; bit++ {
				if op&(1<<bit) != 0 {
					if off >= len(delta) {
						return nil, errors.New("delta: truncated copy offset")
					}
					copyOff |= int(delta[off]) << shift
					off++
				}
				shift += 8
			}
			shift = 0
			for bit := uint(4); bit < 7; bit++ {
				if op&(1<<bit) != 0 {
					if off >= len(delta) {
						return nil, errors.New("delta: truncated copy size")
					}
					copySize |= int(delta[off]) << shift
					off++
				}
				shift += 8
			}
			if copySize == 0 {
				copySize = 0x10000
			}
			if copyOff < 0 || copySize < 0 || copyOff+copySize > len(base) {
				return nil, errors.New("delta: copy out of range")
			}
			if len(out)+copySize > tgtSize {
				return nil, errors.New("delta: output exceeds target size")
			}
			out = append(out, base[copyOff:copyOff+copySize]...)
		} else if op != 0 {
			n := int(op & 0x7f)
			if off+n > len(delta) {
				return nil, errors.New("delta: truncated insert")
			}
			if len(out)+n > tgtSize {
				return nil, errors.New("delta: output exceeds target size")
			}
			out = append(out, delta[off:off+n]...)
			off += n
		} else {
			return nil, errors.New("delta: opcode 0")
		}
	}
	if len(out) != tgtSize {
		return nil, fmt.Errorf("delta: produced %d bytes, expected %d", len(out), tgtSize)
	}
	return out, nil
}
