// Git packfile codec, pack cache and pkt-line framing for the forge.
//
// A pack on the wire is git packfile version 2: a 12-byte header ("PACK",
// version, object count), one zlib stream per object, and a 20-byte SHA-1
// trailer over everything before it. This file only writes whole objects
// (never deltas); it reads whole objects plus ofs-delta and ref-delta
// entries so pushes from real git clients parse correctly.
package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Pack entry type codes, as git numbers them.
const (
	packCommit   = 1
	packTree     = 2
	packBlob     = 3
	packTag      = 4
	packOfsDelta = 6
	packRefDelta = 7
)

var packTypeCodes = map[string]int{
	"commit": packCommit,
	"tree":   packTree,
	"blob":   packBlob,
	"tag":    packTag,
}

var packCodeTypes = map[int]string{
	packCommit: "commit",
	packTree:   "tree",
	packBlob:   "blob",
	packTag:    "tag",
}

// ObjectSHA returns the git object id: SHA-1 over "<type> <len>\0" + raw.
// The header is built with direct byte writes into a stack buffer, no fmt.
func ObjectSHA(typ string, raw []byte) string {
	var hdr [48]byte
	n := copy(hdr[:], typ)
	hdr[n] = ' '
	n++
	// Decimal length, digits produced backwards then copied in order.
	var rev [20]byte
	m := 0
	v := len(raw)
	if v == 0 {
		rev[0] = '0'
		m = 1
	} else {
		for v > 0 {
			rev[m] = byte('0' + v%10)
			v /= 10
			m++
		}
	}
	for i := m - 1; i >= 0; i-- {
		hdr[n] = rev[i]
		n++
	}
	hdr[n] = 0
	n++
	h := sha1.New()
	h.Write(hdr[:n])
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// Pooled zlib readers and writers. A reader is reset onto a fresh bufio
// reader per entry; a writer is reset onto the pack buffer per object.
// Readers go back to the pool only after a clean read to EOF, so a pooled
// reader is never handed out mid-stream.
var zlibReaderPool sync.Pool
var zlibWriterPool sync.Pool

// pooledZlibReader is the interface a pooled zlib reader must satisfy:
// the ReadCloser returned by zlib.NewReader plus the Reset method its
// concrete type carries (the type itself is unexported in compress/zlib).
type pooledZlibReader interface {
	io.ReadCloser
	Reset(io.Reader, []byte) error
}

func acquireZlibReader(r io.Reader) (pooledZlibReader, error) {
	if v := zlibReaderPool.Get(); v != nil {
		zr := v.(pooledZlibReader)
		if err := zr.Reset(r, nil); err != nil {
			return nil, err
		}
		return zr, nil
	}
	rc, err := zlib.NewReader(r)
	if err != nil {
		return nil, err
	}
	zr, ok := rc.(pooledZlibReader)
	if !ok {
		rc.Close()
		return nil, errors.New("pack: zlib reader cannot be reset")
	}
	return zr, nil
}

func releaseZlibReader(zr pooledZlibReader) { zlibReaderPool.Put(zr) }

func acquireZlibWriter(w io.Writer) *zlib.Writer {
	if v := zlibWriterPool.Get(); v != nil {
		zw := v.(*zlib.Writer)
		zw.Reset(w)
		return zw
	}
	return zlib.NewWriter(w)
}

func releaseZlibWriter(zw *zlib.Writer) { zlibWriterPool.Put(zw) }

// appendPackObjectHeader appends the type/size varint that starts one pack
// entry: the low 4 bits of the size ride in the first byte next to the
// type, later bytes carry 7 size bits each, high bit set while more follow.
func appendPackObjectHeader(dst []byte, code, size int) []byte {
	first := byte(code<<4) | byte(size&0x0f)
	size >>= 4
	if size == 0 {
		return append(dst, first)
	}
	dst = append(dst, first|0x80)
	for {
		b := byte(size & 0x7f)
		size >>= 7
		if size == 0 {
			return append(dst, b)
		}
		dst = append(dst, b|0x80)
	}
}

// ---------------------------------------------------------------------------
// Pack reading
// ---------------------------------------------------------------------------

// packEntryParsed is one entry as read from the pack, before delta
// resolution. typ/raw/oid are filled in by resolvePackEntries.
type packEntryParsed struct {
	offset     int
	code       int
	size       int
	data       []byte // inflated bytes: object bytes, or delta instructions
	baseOffset int    // ofs-delta only: absolute pack offset of the base
	baseOID    string // ref-delta only
	typ        string
	raw        []byte
	oid        string
	done       bool
}

// ParsePack reads a whole packfile: whole objects plus ofs-delta and
// ref-delta entries (deltas applied recursively). The trailer SHA-1 is
// verified before any entry is trusted. Returned objects are in pack order
// with OIDs computed by ObjectSHA. A ref-delta whose base is not in the
// pack is an error: there is no outside object lookup in this signature.
func ParsePack(data []byte) ([]RawObject, error) {
	if len(data) < 32 {
		return nil, errors.New("pack: too short for header and trailer")
	}
	if string(data[:4]) != "PACK" {
		return nil, errors.New("pack: bad magic")
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("pack: unsupported version %d", version)
	}
	count := int(binary.BigEndian.Uint32(data[8:12]))
	trailerStart := len(data) - 20
	want := sha1.Sum(data[:trailerStart])
	if !bytes.Equal(want[:], data[trailerStart:]) {
		return nil, errors.New("pack: trailer checksum mismatch")
	}
	entries, err := readPackEntries(data, count, trailerStart)
	if err != nil {
		return nil, err
	}
	if _, err := resolvePackEntries(entries); err != nil {
		return nil, err
	}
	out := make([]RawObject, 0, len(entries))
	for _, e := range entries {
		out = append(out, RawObject{Type: e.typ, Raw: e.raw, OID: e.oid})
	}
	return out, nil
}

// readPackEntries walks the entry table between the header and the trailer,
// inflating each entry's zlib stream. It returns an error on any truncation,
// unknown type code, size mismatch or stray byte before the trailer.
func readPackEntries(data []byte, count, trailerStart int) ([]*packEntryParsed, error) {
	entries := make([]*packEntryParsed, 0, count)
	offset := 12
	for i := 0; i < count; i++ {
		if offset >= trailerStart {
			return nil, errors.New("pack: truncated entry table")
		}
		start := offset
		code, size, next, err := readPackEntryHeader(data, offset, trailerStart)
		if err != nil {
			return nil, err
		}
		offset = next
		e := &packEntryParsed{offset: start, code: code, size: size}
		switch code {
		case packOfsDelta:
			back, n2, err := readOfsDeltaBase(data, offset, trailerStart)
			if err != nil {
				return nil, err
			}
			offset = n2
			if back <= 0 || back > start {
				return nil, fmt.Errorf("pack: ofs-delta at %d has bad base distance %d", start, back)
			}
			e.baseOffset = start - back
		case packRefDelta:
			if offset+20 > trailerStart {
				return nil, errors.New("pack: truncated ref-delta base id")
			}
			e.baseOID = hex.EncodeToString(data[offset : offset+20])
			offset += 20
		default:
			if _, ok := packCodeTypes[code]; !ok {
				return nil, fmt.Errorf("pack: unknown entry type %d at %d", code, start)
			}
		}
		raw, used, err := inflatePackEntry(data, offset, trailerStart, size)
		if err != nil {
			return nil, err
		}
		e.data = raw
		offset += used
		entries = append(entries, e)
	}
	if offset != trailerStart {
		return nil, fmt.Errorf("pack: %d stray bytes before trailer", trailerStart-offset)
	}
	return entries, nil
}

// readPackEntryHeader decodes the type/size varint at offset. limit bounds
// the read so a truncated header is an error, not a slice overrun.
func readPackEntryHeader(data []byte, offset, limit int) (code, size, next int, err error) {
	if offset >= limit {
		return 0, 0, 0, errors.New("pack: truncated entry header")
	}
	b := data[offset]
	offset++
	code = int(b>>4) & 0x07
	size = int(b & 0x0f)
	shift := uint(4)
	for b&0x80 != 0 {
		if offset >= limit {
			return 0, 0, 0, errors.New("pack: truncated entry size")
		}
		b = data[offset]
		offset++
		size |= int(b&0x7f) << shift
		shift += 7
		if shift > 63 {
			return 0, 0, 0, errors.New("pack: entry size too long")
		}
	}
	return code, size, offset, nil
}

// readOfsDeltaBase decodes the ofs-delta base distance: each byte adds its
// low 7 bits, with the running value bumped by one before every shift, so
// the distance is the entry offset minus the decoded value.
func readOfsDeltaBase(data []byte, offset, limit int) (back, next int, err error) {
	if offset >= limit {
		return 0, 0, errors.New("pack: truncated ofs-delta base")
	}
	b := data[offset]
	offset++
	back = int(b & 0x7f)
	for b&0x80 != 0 {
		if offset >= limit {
			return 0, 0, errors.New("pack: truncated ofs-delta base")
		}
		b = data[offset]
		offset++
		back = ((back + 1) << 7) | int(b&0x7f)
	}
	return back, offset, nil
}

// inflatePackEntry inflates one zlib stream starting at offset and reports
// how many pack bytes the stream consumed, so the caller can find the next
// entry. The stream is read through a bufio reader: bytes the flate reader
// has not pulled out of it are still buffered, so consumed is exact.
// The inflated length must equal the size declared in the entry header.
func inflatePackEntry(data []byte, offset, limit, want int) ([]byte, int, error) {
	src := bytes.NewReader(data[offset:limit])
	br := bufio.NewReader(src)
	zr, err := acquireZlibReader(br)
	if err != nil {
		return nil, 0, fmt.Errorf("pack: zlib open at %d: %w", offset, err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, 0, fmt.Errorf("pack: zlib inflate at %d: %w", offset, err)
	}
	releaseZlibReader(zr)
	if len(out) != want {
		return nil, 0, fmt.Errorf("pack: entry at %d declares %d bytes, inflated %d", offset, want, len(out))
	}
	// Bytes the stream consumed are the slice length minus everything
	// still unread: what is left in the underlying reader plus what is
	// still buffered in front of it. (Buffered alone is not enough: the
	// bufio reader only pulls 4 KiB at a time, so for a pack larger than
	// that the rest is still sitting in the underlying reader.)
	used := (limit - offset) - src.Len() - br.Buffered()
	if used <= 0 {
		return nil, 0, fmt.Errorf("pack: zlib stream at %d consumed no bytes", offset)
	}
	return out, used, nil
}

// resolvePackEntries turns every parsed entry into its final object:
// whole objects take their type directly, deltas are applied onto their
// resolved base. Resolution is recursive with a cycle guard, so a delta
// may point at a base anywhere in the pack. The offset and oid lookup maps
// are built only when the pack actually contains that delta kind, keeping
// the common whole-objects-only push free of map allocations.
func resolvePackEntries(entries []*packEntryParsed) ([]*packEntryParsed, error) {
	needOffset := false
	needOID := false
	for _, e := range entries {
		if e.code == packOfsDelta {
			needOffset = true
		}
		if e.code == packRefDelta {
			needOID = true
		}
	}
	var byOffset map[int]*packEntryParsed
	if needOffset {
		byOffset = make(map[int]*packEntryParsed, len(entries))
		for _, e := range entries {
			byOffset[e.offset] = e
		}
	}
	var byOID map[string]*packEntryParsed
	if needOID {
		byOID = make(map[string]*packEntryParsed, len(entries))
	}
	resolving := make(map[int]bool, len(entries))
	var resolve func(e *packEntryParsed) error
	resolve = func(e *packEntryParsed) error {
		if e.done {
			return nil
		}
		if resolving[e.offset] {
			return fmt.Errorf("pack: delta cycle at offset %d", e.offset)
		}
		resolving[e.offset] = true
		defer delete(resolving, e.offset)
		switch e.code {
		case packOfsDelta:
			base := byOffset[e.baseOffset]
			if base == nil {
				return fmt.Errorf("pack: ofs-delta base at offset %d missing", e.baseOffset)
			}
			if err := resolve(base); err != nil {
				return err
			}
			raw, err := applyGitDelta(base.raw, e.data)
			if err != nil {
				return err
			}
			e.typ = base.typ
			e.raw = raw
		case packRefDelta:
			base := byOID[e.baseOID]
			if base == nil {
				for _, cand := range entries {
					if cand == e {
						continue
					}
					if err := resolve(cand); err != nil {
						return err
					}
					if cand.oid == e.baseOID {
						base = cand
						break
					}
				}
			}
			if base == nil {
				return fmt.Errorf("pack: ref-delta base %s not in pack", e.baseOID)
			}
			raw, err := applyGitDelta(base.raw, e.data)
			if err != nil {
				return err
			}
			e.typ = base.typ
			e.raw = raw
		default:
			e.typ = packCodeTypes[e.code]
			e.raw = e.data
		}
		e.oid = ObjectSHA(e.typ, e.raw)
		e.done = true
		if needOID {
			byOID[e.oid] = e
		}
		return nil
	}
	for _, e := range entries {
		if err := resolve(e); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// applyGitDelta applies a git delta instruction stream to a base object.
// The stream starts with the base size and result size as varints (7 bits
// per byte, low group first), then copy/insert ops: a high-bit op copies a
// slice of the base (offset bits 0-3, size bits 4-6, size 0 means 65536),
// any other nonzero op inserts that many literal bytes. Opcode 0 and any
// out-of-range copy or over-long result are errors.
func applyGitDelta(base, delta []byte) ([]byte, error) {
	pos := 0
	readSize := func() (int, error) {
		v := 0
		shift := uint(0)
		for {
			if pos >= len(delta) {
				return 0, errors.New("pack: truncated delta size")
			}
			b := delta[pos]
			pos++
			v |= int(b&0x7f) << shift
			shift += 7
			if b&0x80 == 0 {
				break
			}
			if shift > 63 {
				return 0, errors.New("pack: delta size too long")
			}
		}
		return v, nil
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
		return nil, fmt.Errorf("pack: delta expects %d-byte base, got %d", srcSize, len(base))
	}
	if tgtSize > 1<<28 {
		return nil, fmt.Errorf("pack: delta target size %d too large", tgtSize)
	}
	out := make([]byte, 0, tgtSize)
	for pos < len(delta) {
		op := delta[pos]
		pos++
		if op&0x80 != 0 {
			var copyOff, copySize int
			for bit := 0; bit < 4; bit++ {
				if op&(1<<bit) != 0 {
					if pos >= len(delta) {
						return nil, errors.New("pack: truncated delta copy offset")
					}
					copyOff |= int(delta[pos]) << (8 * bit)
					pos++
				}
			}
			for bit := 0; bit < 3; bit++ {
				if op&(0x10<<bit) != 0 {
					if pos >= len(delta) {
						return nil, errors.New("pack: truncated delta copy size")
					}
					copySize |= int(delta[pos]) << (8 * bit)
					pos++
				}
			}
			if copySize == 0 {
				copySize = 0x10000
			}
			if copyOff+copySize > len(base) {
				return nil, errors.New("pack: delta copy outside base")
			}
			if len(out)+copySize > tgtSize {
				return nil, errors.New("pack: delta writes past target size")
			}
			out = append(out, base[copyOff:copyOff+copySize]...)
		} else if op != 0 {
			n := int(op)
			if pos+n > len(delta) {
				return nil, errors.New("pack: truncated delta insert")
			}
			if len(out)+n > tgtSize {
				return nil, errors.New("pack: delta writes past target size")
			}
			out = append(out, delta[pos:pos+n]...)
			pos += n
		} else {
			return nil, errors.New("pack: delta opcode 0 is invalid")
		}
	}
	if len(out) != tgtSize {
		return nil, fmt.Errorf("pack: delta produced %d of %d bytes", len(out), tgtSize)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Pack writing
// ---------------------------------------------------------------------------

// BuildPack writes a version 2 pack of whole objects only, for the oids
// given, in ascending oid order (adjacent duplicates dropped). The trailer
// is the SHA-1 of everything before it. This is the cold path: callers
// serve cached bytes and only build once per pack-cache key.
func BuildPack(snap *RepoSnapshot, oids []string) ([]byte, error) {
	if snap == nil {
		return nil, errors.New("pack: nil snapshot")
	}
	sorted := append([]string(nil), oids...)
	sort.Strings(sorted)
	uniq := sorted[:0]
	for i, oid := range sorted {
		if i == 0 || oid != sorted[i-1] {
			uniq = append(uniq, oid)
		}
	}
	sorted = uniq
	var out bytes.Buffer
	out.Grow(64 + len(sorted)*64)
	var head [12]byte
	copy(head[0:4], "PACK")
	binary.BigEndian.PutUint32(head[4:8], 2)
	binary.BigEndian.PutUint32(head[8:12], uint32(len(sorted)))
	out.Write(head[:])
	for _, oid := range sorted {
		obj, ok := snap.Objects[oid]
		if !ok || obj == nil {
			return nil, fmt.Errorf("pack: object %s not in snapshot", oid)
		}
		code, ok := packTypeCodes[obj.Type]
		if !ok {
			return nil, fmt.Errorf("pack: unknown object type %q", obj.Type)
		}
		out.Write(appendPackObjectHeader(nil, code, len(obj.Raw)))
		zw := acquireZlibWriter(&out)
		if _, err := zw.Write(obj.Raw); err != nil {
			return nil, fmt.Errorf("pack: deflate %s: %w", oid, err)
		}
		if err := zw.Close(); err != nil {
			return nil, fmt.Errorf("pack: deflate close %s: %w", oid, err)
		}
		releaseZlibWriter(zw)
	}
	sum := sha1.Sum(out.Bytes())
	out.Write(sum[:])
	return out.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Pack cache (single-flight)
// ---------------------------------------------------------------------------

// PackCacheKey names one built pack: the repo generation it was built from,
// the wanted and had object ids, and the fetch depth. Wants and Haves are
// joined id lists; String sorts each list so the same set spells one key.
type PackCacheKey struct {
	Generation uint64
	Wants      string
	Haves      string
	Depth      int
}

func (k PackCacheKey) String() string {
	var b strings.Builder
	b.WriteString("gen=")
	b.WriteString(strconv.FormatUint(k.Generation, 10))
	b.WriteString("|wants=")
	b.WriteString(sortedKeyPart(k.Wants))
	b.WriteString("|haves=")
	b.WriteString(sortedKeyPart(k.Haves))
	b.WriteString("|depth=")
	b.WriteString(strconv.Itoa(k.Depth))
	return b.String()
}

// sortedKeyPart orders the comma/space separated ids in one key part.
func sortedKeyPart(s string) string {
	if !strings.ContainsAny(s, ", ") {
		return s
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

type packEntry struct {
	done chan struct{}
	data []byte
	err  error
}

// PackCache memoizes built packs by key. The first caller for a key runs
// the build; concurrent callers for the same key wait on its done channel
// and share the result, so one generation is built once even under a burst
// of identical fetches. A failed build is not cached: the entry is dropped
// once its waiters have been told, so the next caller retries.
type PackCache struct {
	mu sync.Mutex
	m  map[string]*packEntry
}

func NewPackCache() *PackCache {
	return &PackCache{m: make(map[string]*packEntry)}
}

func (c *PackCache) GetOrBuild(key PackCacheKey, build func() ([]byte, error)) ([]byte, error) {
	name := key.String()
	c.mu.Lock()
	if e, ok := c.m[name]; ok {
		c.mu.Unlock()
		<-e.done
		return e.data, e.err
	}
	e := &packEntry{done: make(chan struct{})}
	c.m[name] = e
	c.mu.Unlock()
	data, err := build()
	e.data = data
	e.err = err
	close(e.done)
	if err != nil {
		c.mu.Lock()
		if c.m[name] == e {
			delete(c.m, name)
		}
		c.mu.Unlock()
	}
	return data, err
}

// ---------------------------------------------------------------------------
// Pkt-line and sideband framing
// ---------------------------------------------------------------------------

func hexNibble(v int) byte {
	if v < 10 {
		return byte('0' + v)
	}
	return byte('a' + v - 10)
}

// EncodePktLine frames data as one pkt-line: a 4-hex-digit length prefix
// (payload plus the 4 prefix bytes) followed by the payload. Panics on a
// payload over the 65520-byte pkt-line maximum; callers that frame large
// blobs must split first, as EncodeSideband does.
func EncodePktLine(data []byte) []byte {
	n := len(data) + 4
	if n > 65520 {
		panic("pack: pkt-line payload exceeds 65520 bytes")
	}
	out := make([]byte, 0, n)
	out = append(out, hexNibble(n>>12), hexNibble((n>>8)&0xf), hexNibble((n>>4)&0xf), hexNibble(n&0xf))
	out = append(out, data...)
	return out
}

// EncodeFlush returns the flush packet "0000".
func EncodeFlush() []byte {
	return []byte{'0', '0', '0', '0'}
}

func parsePktLen(b []byte) (int, error) {
	n := 0
	for _, c := range b {
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'f':
			v = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = int(c-'A') + 10
		default:
			return 0, errors.New("pack: bad pkt-line length")
		}
		n = n*16 + v
	}
	return n, nil
}

// DecodePktLines splits a whole pkt-line stream into payloads. Control
// packets (flush 0000, delim 0001, response-end 0002) come back as a nil
// entry each, so a caller can tell where a section ended. Any truncation,
// bad length digit or over-long packet is an error.
func DecodePktLines(data []byte) ([][]byte, error) {
	var out [][]byte
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, errors.New("pack: truncated pkt-line")
		}
		n, err := parsePktLen(data[:4])
		if err != nil {
			return nil, err
		}
		switch n {
		case 0, 1, 2:
			out = append(out, nil)
			data = data[4:]
		default:
			if n < 4 || n > 65520 {
				return nil, fmt.Errorf("pack: bad pkt-line length %d", n)
			}
			if len(data) < n {
				return nil, errors.New("pack: truncated pkt-line")
			}
			payload := make([]byte, n-4)
			copy(payload, data[4:n])
			out = append(out, payload)
			data = data[n:]
		}
	}
	return out, nil
}

// EncodeSideband frames data for sideband-64k: each frame is one pkt-line
// holding a band byte followed by a slice of the data, split so no frame
// tops the 65520-byte pkt-line maximum (4 header + 1 band + 65515 data).
// Empty data frames nothing.
func EncodeSideband(band byte, data []byte) []byte {
	const maxData = 65520 - 4 - 1
	if len(data) == 0 {
		return nil
	}
	var out []byte
	for len(data) > 0 {
		take := len(data)
		if take > maxData {
			take = maxData
		}
		frame := make([]byte, 0, take+1)
		frame = append(frame, band)
		frame = append(frame, data[:take]...)
		out = append(out, EncodePktLine(frame)...)
		data = data[take:]
	}
	return out
}
