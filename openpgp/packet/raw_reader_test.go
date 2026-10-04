// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// ---- sample builders -------------------------------------------------------

// definiteLengthBytes returns the new-format definite length encoding.
func definiteLengthBytes(n int) []byte {
	switch {
	case n < 192:
		return []byte{byte(n)}
	case n < 8384:
		l := n - 192
		return []byte{192 + byte(l>>8), byte(l)}
	default:
		return []byte{255, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// newFixedPacket builds a new-format definite-length packet.
func newFixedPacket(tag uint8, body []byte) []byte {
	out := []byte{0xc0 | (tag & 0x3f)}
	out = append(out, definiteLengthBytes(len(body))...)
	return append(out, body...)
}

// oldLengthType describes an old-format definite length encoding.
// type 0 -> 1 octet, 1 -> 2 octets, 2 -> 4 octets.
func oldFixedPacket(tag uint8, body []byte, lengthType byte) []byte {
	out := []byte{0x80 | ((tag & 0x3f) << 2) | (lengthType & 0x03)}
	n := 1 << lengthType
	for i := n - 1; i >= 0; i-- {
		out = append(out, byte(len(body)>>(8*uint(i))))
	}
	return append(out, body...)
}

// partialLengthByte returns the partial length octet for chunk size 2^power.
func partialLengthByte(power uint) byte { return byte(224 + power) }

// partialPacket builds a new-format packet whose body is encoded as zero or
// more partial chunks followed by one definite final chunk. powers are the
// chunk powers of two; final is the size of the final chunk.
func partialPacket(tag uint8, body []byte, powers []uint, final int) []byte {
	out := []byte{0xc0 | (tag & 0x3f)}
	if len(powers) == 0 {
		// Header holds the first (and only) definite length directly.
		out = append(out, definiteLengthBytes(final)...)
		return append(out, body...)
	}
	pos := 0
	for i, power := range powers {
		size := 1 << power
		if i == 0 {
			out = append(out, partialLengthByte(power))
		} else {
			out = append(out, partialLengthByte(power))
		}
		out = append(out, body[pos:pos+size]...)
		pos += size
	}
	if pos+final != len(body) {
		panic("partial chunks + final do not match body size")
	}
	out = append(out, definiteLengthBytes(final)...)
	out = append(out, body[pos:]...)
	return out
}

func payload(seed, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(seed*7 + i*13)
	}
	return b
}

// ---- split-then-merge round trip ------------------------------------------

// expectedPacket is the metadata verified while walking a stream.
type expectedPacket struct {
	tag      uint8
	offset   int64
	partial  bool
	fixedLen int64
	// logical body without partial length octets
	body []byte
}

func walkAndRebuild(t *testing.T, stream []byte, expected []expectedPacket, copyWith func(*RawPacket, io.Writer) (int64, error)) {
	t.Helper()
	var rebuilt bytes.Buffer
	r := NewRawReader(bytes.NewReader(stream))
	for i, want := range expected {
		p, err := r.Next()
		if err != nil {
			t.Fatalf("packet #%d Next: %v", i+1, err)
		}
		if p.Tag != want.tag || p.StartOffset != want.offset ||
			p.Partial != want.partial || p.FixedLength != want.fixedLen {
			t.Fatalf("packet #%d metadata = tag %d off %d partial %v len %d; want tag %d off %d partial %v len %d",
				i+1, p.Tag, p.StartOffset, p.Partial, p.FixedLength,
				want.tag, want.offset, want.partial, want.fixedLen)
		}
		before := rebuilt.Len()
		if _, err := copyWith(p, &rebuilt); err != nil {
			t.Fatalf("packet #%d copy: %v", i+1, err)
		}
		if !bytes.Equal(rebuilt.Bytes()[before:], stream[before:rebuilt.Len()]) {
			t.Fatalf("packet #%d bytes diverged from wire: got %x want %x (header %x)",
				i+1, rebuilt.Bytes()[before:], stream[before:rebuilt.Len()], p.Header)
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("expected EOF after all packets, got %v", err)
	}
	if !bytes.Equal(rebuilt.Bytes(), stream) {
		t.Fatalf("rebuilt stream is not byte-identical")
	}
}

// bodyStream strips partial length octets to obtain the logical contents.
// For partial packets the first length octet lives in p.Header, so the body
// stream starts with the first chunk's data rather than a length octet.
func bodyStream(t *testing.T, p *RawPacket) []byte {
	t.Helper()
	raw, err := io.ReadAll(p)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !p.Partial {
		return raw
	}
	var out []byte
	chunkLeft := 1 << (p.Header[len(p.Header)-1] & 0x1f)
	firstChunk := true
	for i := 0; i < len(raw); {
		if firstChunk && chunkLeft > 0 {
			take := chunkLeft
			if take > len(raw)-i {
				take = len(raw) - i
			}
			out = append(out, raw[i:i+take]...)
			i += take
			chunkLeft -= take
			if chunkLeft == 0 {
				firstChunk = false
			}
			continue
		}
		firstChunk = false
		b := raw[i]
		i++
		var l int
		switch {
		case b < 192:
			l = int(b)
		case b < 224:
			l = int(b-192)<<8 + int(raw[i]) + 192
			i++
		case b < 255:
			l = 1 << (b & 0x1f)
		default:
			l = int(raw[i])<<24 | int(raw[i+1])<<16 | int(raw[i+2])<<8 | int(raw[i+3])
			i += 4
		}
		out = append(out, raw[i:i+l]...)
		i += l
	}
	return out
}

func TestRawReaderSplitAndMerge(t *testing.T) {
	// Same logical message, two encodings for the fixed-length packets.
	body30, body300, body1000 := payload(2, 30), payload(3, 300), payload(4, 1000)

	newStream := func() []byte {
		var s []byte
		s = append(s, newFixedPacket(10, []byte{1, 2, 3})...) // marker: not skipped
		s = append(s, newFixedPacket(30, payload(1, 5))...)   // unknown tag 30
		s = append(s, newFixedPacket(11, body30)...)          // 1-octet
		s = append(s, newFixedPacket(6, body300)...)          // 2-octet
		s = append(s, newFixedPacket(2, body1000)...)         // 2-octet
		return s
	}
	oldStream := func() []byte {
		var s []byte
		s = append(s, oldFixedPacket(10, []byte{1, 2, 3}, 0)...)
		s = append(s, oldFixedPacket(12, payload(1, 5), 0)...) // trust tag: must not be skipped
		s = append(s, oldFixedPacket(11, body30, 0)...)
		s = append(s, oldFixedPacket(6, body300, 1)...)  // 2-octet old
		s = append(s, oldFixedPacket(2, body1000, 2)...) // 4-octet old
		return s
	}

	type pspec struct {
		tag  uint8
		body []byte
	}
	newSpecs := []pspec{{10, []byte{1, 2, 3}}, {30, payload(1, 5)}, {11, body30}, {6, body300}, {2, body1000}}
	oldSpecs := []pspec{{10, []byte{1, 2, 3}}, {12, payload(1, 5)}, {11, body30}, {6, body300}, {2, body1000}}
	buildExpected := func(s []byte, specs []pspec) []expectedPacket {
		want := make([]expectedPacket, len(specs))
		off := int64(0)
		tmp := NewRawReader(bytes.NewReader(s))
		for i := range specs {
			p, err := tmp.Next()
			if err != nil {
				t.Fatalf("expected walk: %v", err)
			}
			want[i] = expectedPacket{
				tag: specs[i].tag, offset: off, fixedLen: int64(len(specs[i].body)), body: specs[i].body,
			}
			if err := p.Discard(); err != nil {
				t.Fatalf("expected walk discard: %v", err)
			}
			off = p.r.pos
		}
		return want
	}

	for _, tc := range []struct {
		stream func() []byte
		specs  []pspec
	}{{newStream, newSpecs}, {oldStream, oldSpecs}} {
		stream := tc.stream()
		want := buildExpected(stream, tc.specs)

		// Copy via WriteTo: header + body streamed verbatim.
		walkAndRebuild(t, stream, want, func(p *RawPacket, w io.Writer) (int64, error) {
			return p.WriteTo(w)
		})

		// Copy via explicit header write + streaming body Read.
		walkAndRebuild(t, stream, want, func(p *RawPacket, w io.Writer) (int64, error) {
			n, err := w.Write(p.Header)
			if err != nil {
				return int64(n), err
			}
			m, err := copyBody(w, p)
			return int64(n) + m, err
		})

		// Skip via Discard and verify logical bodies on a second walk.
		r := NewRawReader(bytes.NewReader(stream))
		for i, wp := range want {
			p, err := r.Next()
			if err != nil {
				t.Fatalf("discard walk #%d: %v", i, err)
			}
			got := bodyStream(t, p)
			if !bytes.Equal(got, wp.body) {
				t.Fatalf("packet #%d logical body mismatch", i+1)
			}
			if err := p.Discard(); err != nil {
				t.Fatalf("discard after full read: %v", err)
			}
		}
	}

	// Fixed samples with different header encodings but identical contents.
	a := newFixedPacket(11, body300)
	b := oldFixedPacket(11, body300, 1)
	if bytes.Equal(a, b) {
		t.Fatalf("samples should differ on the wire")
	}
	if !bytes.Equal(
		bodyStream(t, mustNext(t, a)),
		bodyStream(t, mustNext(t, b))) {
		t.Fatalf("differently encoded packets have different logical contents")
	}
	// Yet each splits and merges back to its exact bytes.
	for _, s := range [][]byte{a, b} {
		var out bytes.Buffer
		if _, err := mustNext(t, s).WriteTo(&out); err != nil {
			t.Fatalf("single WriteTo: %v", err)
		}
		if !bytes.Equal(out.Bytes(), s) {
			t.Fatalf("single packet round-trip mismatch")
		}
	}
}

func mustNext(t *testing.T, s []byte) *RawPacket {
	t.Helper()
	p, err := NewRawReader(bytes.NewReader(s)).Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return p
}

// copyBody streams only the packet body (no header) via Read, deliberately
// avoiding io.Copy which would dispatch to RawPacket.WriteTo and repeat the
// header.
func copyBody(w io.Writer, p *RawPacket) (int64, error) {
	var buf [4096]byte
	var total int64
	for {
		n, err := p.Read(buf[:])
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func TestRawReaderPartial(t *testing.T) {
	cases := []struct {
		name   string
		powers []uint
		final  int
	}{
		{"partial 16+512 then 7", []uint{4, 9}, 7},
		{"partial 1024 then 2-octet final", []uint{10}, 400},
		{"partial 512 then 5-octet final", []uint{9}, 70000},
		{"zero length final", []uint{3}, 0},
		{"two equal chunks", []uint{5, 5}, 11},
	}
	tags := []uint8{13, 17, 21, 14, 8}
	for i, tc := range cases {
		tag := tags[i]
		total := tc.final
		for _, pw := range tc.powers {
			total += 1 << pw
		}
		body := payload(50+i, total)
		wire := partialPacket(tag, body, tc.powers, tc.final)

		r := NewRawReader(bytes.NewReader(wire))
		p, err := r.Next()
		if err != nil {
			t.Fatalf("%s: Next: %v", tc.name, err)
		}
		if !p.Partial || p.FixedLength != -1 || p.Tag != tag || p.StartOffset != 0 {
			t.Fatalf("%s: metadata = tag %d partial %v len %d", tc.name, p.Tag, p.Partial, p.FixedLength)
		}
		// Header is exactly the tag byte plus the first partial length octet.
		if !bytes.Equal(p.Header, []byte{0xc0 | tag, partialLengthByte(tc.powers[0])}) {
			t.Fatalf("%s: header bytes % x", tc.name, p.Header)
		}

		// Logical body equals the payload.
		got := bodyStream(t, p)
		if !bytes.Equal(got, body) {
			t.Fatalf("%s: logical body mismatch", tc.name)
		}
		// Consumed counts data plus all intra-body length octets: the wire
		// body size is payload size + number of length octets inside the body
		// (all partial length octets except the first one in the header,
		// plus the final definite length encoding, which is 1 octet here).
		extraLen := len(tc.powers) - 1 + len(definiteLengthBytes(tc.final))
		if p.Consumed != int64(len(body)+extraLen) {
			t.Fatalf("%s: consumed %d, want %d", tc.name, p.Consumed, len(body)+extraLen)
		}
		if err := p.Discard(); err != nil {
			t.Fatalf("%s: discard: %v", tc.name, err)
		}

		// Raw reconstruction (header + raw body) must equal the wire bytes.
		r2 := NewRawReader(bytes.NewReader(wire))
		p2, _ := r2.Next()
		var raw bytes.Buffer
		if _, err := p2.WriteTo(&raw); err != nil {
			t.Fatalf("%s: WriteTo: %v", tc.name, err)
		}
		if !bytes.Equal(raw.Bytes(), wire) {
			t.Fatalf("%s: partial reconstruction differs from wire", tc.name)
		}
	}
}

// ---- streaming / laziness -------------------------------------------------

// countingReader counts every byte pulled from the underlying reader.
type countingReader struct {
	r     io.Reader
	count int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.count += int64(n)
	return n, err
}

func (c *countingReader) ReadByte() (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(c, b[:])
	return b[0], err
}

func TestRawReaderMetadataIsLazy(t *testing.T) {
	// First packet has a small 2-byte header; the rest is megabytes of body
	// plus another packet that must never be touched up front.
	const firstBody = 200_000
	stream := newFixedPacket(11, payload(1, firstBody))
	stream = append(stream, newFixedPacket(6, payload(2, 300))...)

	cr := &countingReader{r: bytes.NewReader(stream)}
	rr := NewRawReader(cr)

	p, err := rr.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(p.Header) != 6 {
		t.Fatalf("expected 6-byte five-octet length header, got %d bytes", len(p.Header))
	}
	// Only the two header bytes must have been pulled: reading metadata of
	// the first packet does not slurp later content into memory.
	if cr.count != int64(len(p.Header)) {
		t.Fatalf("Next read %d bytes, want only the %d header bytes", cr.count, len(p.Header))
	}
	if cr.count >= int64(firstBody) {
		t.Fatalf("metadata read touched the body")
	}

	// Discarding streams the body without buffering.
	if err := p.Discard(); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if cr.count != int64(firstBody+len(p.Header)) {
		t.Fatalf("after discard read %d, want %d", cr.count, firstBody+len(p.Header))
	}

	// Second packet header only, again.
	p2, err := rr.Next()
	if err != nil {
		t.Fatalf("second Next: %v", err)
	}
	if cr.count != int64(firstBody+len(p.Header)+len(p2.Header)) {
		t.Fatalf("second header over-read: %d", cr.count)
	}
	if err := p2.Discard(); err != nil {
		t.Fatalf("second discard: %v", err)
	}
	if _, err := rr.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestRawReaderNextBeforeFinish(t *testing.T) {
	stream := newFixedPacket(11, payload(1, 50))
	stream = append(stream, newFixedPacket(6, payload(2, 10))...)
	rr := NewRawReader(bytes.NewReader(stream))

	p, err := rr.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	// Read only part of the body, then try to advance.
	half := make([]byte, 10)
	if _, err := io.ReadFull(p, half); err != nil {
		t.Fatalf("partial read: %v", err)
	}
	if _, err := rr.Next(); err == nil {
		t.Fatalf("expected error when advancing before finishing packet")
	}
	// The state must be unchanged: finishing the first packet then advancing
	// works and exposes the exact second packet.
	if err := p.Discard(); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	p2, err := rr.Next()
	if err != nil {
		t.Fatalf("Next after discard: %v", err)
	}
	if p2.Tag != 6 {
		t.Fatalf("second packet tag = %d, want 6", p2.Tag)
	}
	rest, err := io.ReadAll(p2)
	if err != nil {
		t.Fatalf("second body: %v", err)
	}
	if !bytes.Equal(rest, payload(2, 10)) {
		t.Fatalf("second body corrupted")
	}
}

// ---- truncation -----------------------------------------------------------

func expectTruncated(t *testing.T, name string, data []byte, wantNumber int, wantTag uint8) {
	t.Helper()
	rr := NewRawReader(bytes.NewReader(data))
	for {
		p, err := rr.Next()
		if err == io.EOF {
			t.Fatalf("%s: expected truncation, got clean EOF", name)
		}
		if err != nil {
			checkTruncation(t, name, err, wantNumber, wantTag)
			return
		}
		if _, err := io.Copy(io.Discard, p); err != nil {
			checkTruncation(t, name, err, wantNumber, wantTag)
			return
		}
	}
}

func checkTruncation(t *testing.T, name string, err error, wantNumber int, wantTag uint8) {
	t.Helper()
	te, ok := err.(*errors.TruncatedPacketError)
	if !ok {
		t.Fatalf("%s: want TruncatedPacketError, got %v", name, err)
	}
	if te.PacketNumber != wantNumber || te.Tag != wantTag {
		t.Fatalf("%s: truncation #%d tag %d, want #%d tag %d",
			name, te.PacketNumber, te.Tag, wantNumber, wantTag)
	}
}

func TestRawReaderTruncation(t *testing.T) {
	body := payload(7, 100)

	// New-format fixed packet whose declared length exceeds available body.
	full := newFixedPacket(11, body)
	expectTruncated(t, "fixed body cut", full[:len(full)-3], 1, 11)

	// Two-octet length in header, body cut.
	big := newFixedPacket(6, payload(8, 300))
	expectTruncated(t, "2-octet body cut", big[:len(big)-10], 1, 6)

	// Five-octet length header itself truncated.
	truncHeader := []byte{0xc0 | 11, 255, 0, 1}
	expectTruncated(t, "5-octet header cut", truncHeader, 1, 11)

	// Old-format 4-octet length header truncated.
	expectTruncated(t, "old header cut", []byte{0x80 | (11 << 2) | 2, 0, 0}, 1, 11)

	// Partial packet: final definite chunk declared but body missing.
	partialBody := payload(9, 512+5)
	partialWire := partialPacket(13, partialBody, []uint{9}, 5)
	expectTruncated(t, "partial final body cut", partialWire[:len(partialWire)-2], 1, 13)

	// Partial packet: stream ends right when another length octet is needed.
	// tag, first partial length (512 bytes), 512 data bytes, then a partial
	// length octet promising another chunk that never arrives.
	dangling := append([]byte{0xc0 | 13, partialLengthByte(9)}, payload(9, 512)...)
	dangling = append(dangling, partialLengthByte(4))
	expectTruncated(t, "partial dangling length", dangling, 1, 13)

	// Second packet truncated: packet number and offset identify it.
	two := newFixedPacket(11, payload(1, 20))
	secondStart := len(two)
	two = append(two, newFixedPacket(6, payload(2, 40))...)
	two = two[:len(two)-5]
	rr := NewRawReader(bytes.NewReader(two))
	p1, err := rr.Next()
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if err := p1.Discard(); err != nil {
		t.Fatalf("first discard: %v", err)
	}
	p2, err := rr.Next()
	if err != nil {
		t.Fatalf("second Next: %v", err)
	}
	if p2.Tag != 6 || p2.StartOffset != int64(secondStart) {
		t.Fatalf("second metadata tag %d off %d", p2.Tag, p2.StartOffset)
	}
	_, err = io.Copy(io.Discard, p2)
	te, ok := err.(*errors.TruncatedPacketError)
	if !ok {
		t.Fatalf("want TruncatedPacketError, got %v", err)
	}
	if te.PacketNumber != 2 || te.Tag != 6 || te.Offset != int64(len(two)) {
		t.Fatalf("truncation locator = #%d tag %d off %d", te.PacketNumber, te.Tag, te.Offset)
	}
}

// ---- old-format indeterminate length --------------------------------------

func TestRawReaderIndeterminate(t *testing.T) {
	body := payload(3, 1234)
	// Old format, tag 11, length type 3 (indeterminate).
	wire := append([]byte{0x80 | (11 << 2) | 3}, body...)

	rr := NewRawReader(bytes.NewReader(wire))
	p, err := rr.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if p.Tag != 11 || p.FixedLength != -1 || !bytes.Equal(p.Header, wire[:1]) {
		t.Fatalf("indeterminate metadata wrong: tag %d len %d header %x", p.Tag, p.FixedLength, p.Header)
	}
	got, err := io.ReadAll(p)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("indeterminate body mismatch")
	}
	if _, err := rr.Next(); err != io.EOF {
		t.Fatalf("want EOF after indeterminate packet, got %v", err)
	}

	// A definite packet followed by an indeterminate one: the indeterminate
	// packet absorbs everything trailing it, so there is no third packet.
	two := newFixedPacket(6, payload(1, 7))
	two = append(two, wire...)
	two = append(two, 0xc0|2, 5) // bytes that look like another header
	rr = NewRawReader(bytes.NewReader(two))
	p1, _ := rr.Next()
	if err := p1.Discard(); err != nil {
		t.Fatalf("discard first: %v", err)
	}
	p2, err := rr.Next()
	if err != nil {
		t.Fatalf("indeterminate Next: %v", err)
	}
	got, _ = io.ReadAll(p2)
	if !bytes.HasSuffix(got, []byte{0xc0 | 2, 5}) {
		t.Fatalf("bytes after indeterminate packet must be part of its body")
	}
	if _, err := rr.Next(); err != io.EOF {
		t.Fatalf("indeterminate packet must be the final packet, got %v", err)
	}
}

// ---- reader returning data together with EOF ------------------------------

// eagerEOFReader behaves like a reader that returns the final bytes together
// with io.EOF on every call, which is legal per the io.Reader contract.
type eagerEOFReader struct {
	data []byte
	pos  int
}

func (e *eagerEOFReader) Read(p []byte) (int, error) {
	if e.pos >= len(e.data) {
		return 0, io.EOF
	}
	n := copy(p, e.data[e.pos:])
	e.pos += n
	return n, io.EOF
}

func TestRawReaderDataWithEOF(t *testing.T) {
	// A single packet: the reader may legitimately return io.EOF together
	// with the final bytes because nothing follows the packet.
	stream := newFixedPacket(11, payload(1, 7))
	rr := NewRawReader(&eagerEOFReader{data: stream})

	var rebuilt bytes.Buffer
	p, err := rr.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, err := p.WriteTo(&rebuilt); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if _, err := rr.Next(); err != io.EOF {
		t.Fatalf("want final EOF, got %v", err)
	}
	if !bytes.Equal(rebuilt.Bytes(), stream) {
		t.Fatalf("eager-EOF round-trip mismatch")
	}
}
