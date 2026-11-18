// Pkt-line framing and packfile codec for the git protocol.
//
// The pkt-line helpers frame the smart-HTTP streams. BuildPack assembles
// version-2 packfiles from whole objects (no deltas are written); ParsePack
// decodes packfiles with full OFS_DELTA and REF_DELTA resolution, including
// delta chains, and verifies the trailer checksum. ParsePackWithResolver
// additionally resolves thin-pack REF_DELTA bases already held in the store.

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
	"strconv"
)

// PktFlushBytes is the flush packet ("0000").
var PktFlushBytes = []byte("0000")

// PktDelimBytes is the delimiter packet ("0001").
var PktDelimBytes = []byte("0001")

// EncodePktLine frames payload as one pkt-line: a 4-hex-digit length
// (including the 4 length bytes) followed by the payload.
func EncodePktLine(payload []byte) ([]byte, error) {
	n := len(payload) + 4
	if n > 0xffff {
		return nil, fmt.Errorf("pkt-line too large: %d bytes", len(payload))
	}
	out := make([]byte, 0, n)
	out = append(out, []byte(fmt.Sprintf("%04x", n))...)
	out = append(out, payload...)
	return out, nil
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
func DecodePktLines(data []byte) ([]PktLine, error) {
	var lines []PktLine
	rest := data
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, errors.New("pkt-line: truncated length prefix")
		}
		n64, err := strconv.ParseUint(string(rest[:4]), 16, 16)
		if err != nil {
			return nil, fmt.Errorf("pkt-line: bad length %q", string(rest[:4]))
		}
		n := int(n64)
		switch n {
		case 0:
			lines = append(lines, PktLine{Flush: true})
			rest = rest[4:]
		case 1:
			lines = append(lines, PktLine{Delim: true})
			rest = rest[4:]
		case 2:
			lines = append(lines, PktLine{End: true})
			rest = rest[4:]
		default:
			if n < 4 || n > len(rest) {
				return nil, fmt.Errorf("pkt-line: length %d out of range", n)
			}
			lines = append(lines, PktLine{Payload: rest[4:n]})
			rest = rest[n:]
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

// gitPackTypeCode maps an object type to its pack type code.
func gitPackTypeCode(t ObjectType) (int, bool) {
	switch t {
	case ObjCommit:
		return 1, true
	case ObjTree:
		return 2, true
	case ObjBlob:
		return 3, true
	case ObjTag:
		return 4, true
	}
	return 0, false
}

// gitPackTypeFromCode maps a pack type code back to an object type.
func gitPackTypeFromCode(code int) (ObjectType, bool) {
	switch code {
	case 1:
		return ObjCommit, true
	case 2:
		return ObjTree, true
	case 3:
		return ObjBlob, true
	case 4:
		return ObjTag, true
	}
	return 0, false
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

// BuildPack assembles a version-2 packfile holding the given objects, in the
// given order, as whole objects (no deltas). The output is deterministic for
// identical inputs: same order, same compression level, trailer SHA-1 over
// all preceding bytes.
func BuildPack(objects []*GitObject) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(12 + len(objects)*64)
	var header [12]byte
	copy(header[0:4], "PACK")
	binary.BigEndian.PutUint32(header[4:8], 2)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(objects)))
	buf.Write(header[:])
	zw := zlib.NewWriter(&buf)
	for i, obj := range objects {
		if obj == nil {
			return nil, errors.New("pack: nil object")
		}
		code, ok := gitPackTypeCode(obj.Type)
		if !ok {
			return nil, fmt.Errorf("pack: unknown object type %v", obj.Type)
		}
		var hb [10]byte
		buf.Write(gitPackAppendHeader(hb[:0], code, len(obj.Raw)))
		if i > 0 {
			zw.Reset(&buf)
		}
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
	entries := make([]*gitPackEntry, 0, min(count, 4096))
	byOffset := make(map[int]*gitPackEntry, min(count, 4096))
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
		// Inflate exactly one zlib stream. bytes.Reader is an io.ByteReader,
		// so the flate reader consumes exactly the stream's bytes and the
		// reader's remaining length gives the next entry's offset.
		br := bytes.NewReader(data[offset:trailerStart])
		zr, err := zlib.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("pack: zlib stream at %d: %w", offset, err)
		}
		inflated, err := io.ReadAll(io.LimitReader(zr, int64(size)+1))
		_ = zr.Close()
		if err != nil {
			return nil, fmt.Errorf("pack: inflate at %d: %w", offset, err)
		}
		if len(inflated) != size {
			return nil, fmt.Errorf("pack: entry at %d declares %d bytes, inflated %d", entryOffset, size, len(inflated))
		}
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
