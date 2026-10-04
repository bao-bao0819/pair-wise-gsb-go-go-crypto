// Copyright 2026 The ProtonMail Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// rawTestContents returns the fixed 200-byte content shared by all
// header-encoding samples below.
func rawTestContents() []byte {
	contents := make([]byte, 200)
	for i := range contents {
		contents[i] = byte(i)
	}
	return contents
}

// rawTestSamples encodes the same 200-byte body with every supported
// header and length encoding. Tag 13 (User ID) is used for the known-tag
// samples; tag 60 is a private/experimental tag unknown to this package.
func rawTestSamples() map[string][]byte {
	c := rawTestContents()
	samples := map[string][]byte{
		// Old format, one-octet length.
		"old-1byte": {0xB4, 0xC8},
		// Old format, two-octet length.
		"old-2byte": {0xB5, 0x00, 0xC8},
		// Old format, four-octet length.
		"old-4byte": {0xB6, 0x00, 0x00, 0x00, 0xC8},
		// New format, two-octet length (200 = 0xC0, 0x08).
		"new-2byte": {0xCD, 0xC0, 0x08},
		// New format, five-octet length.
		"new-5byte": {0xCD, 0xFF, 0x00, 0x00, 0x00, 0xC8},
		// New format, unknown (private) tag 60, two-octet length.
		"unknown-tag": {0xFC, 0xC0, 0x08},
		// Old format, indeterminate length: body runs to EOF.
		"old-indeterminate": {0xB7},
	}
	for name, header := range samples {
		samples[name] = append(header, c...)
	}
	// New format, partial body: segments of 128, 64 and a final 8 bytes.
	partial := []byte{0xCD, 0xE7}
	partial = append(partial, c[:128]...)
	partial = append(partial, 0xE6)
	partial = append(partial, c[128:192]...)
	partial = append(partial, 0x08)
	partial = append(partial, c[192:]...)
	samples["new-partial"] = partial
	return samples
}

// splitMerge reads all packets from input and reassembles them with
// CopyTo, returning the reassembled stream.
func splitMerge(t *testing.T, input []byte) ([]byte, []*RawPacket) {
	t.Helper()
	rr := NewRawReader(bytes.NewReader(input))
	var out bytes.Buffer
	var packets []*RawPacket
	for {
		pkt, err := rr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next() packet %d: %v", len(packets), err)
		}
		if _, err := pkt.CopyTo(&out); err != nil {
			t.Fatalf("CopyTo() packet %d: %v", len(packets), err)
		}
		packets = append(packets, pkt)
	}
	return out.Bytes(), packets
}

// TestRawReaderSplitMerge proves that splitting each sample into packets
// and merging it back reproduces the input byte-for-byte, for every
// header and length encoding.
func TestRawReaderSplitMerge(t *testing.T) {
	for name, sample := range rawTestSamples() {
		out, packets := splitMerge(t, sample)
		if !bytes.Equal(out, sample) {
			t.Errorf("%s: split+merge mismatch:\ngot  %x\nwant %x", name, out, sample)
		}
		if len(packets) != 1 {
			t.Fatalf("%s: got %d packets, want 1", name, len(packets))
		}
		pkt := packets[0]
		if pkt.Offset != 0 || pkt.Seq != 0 {
			t.Errorf("%s: got seq=%d offset=%d, want 0/0", name, pkt.Seq, pkt.Offset)
		}
	}
}

// TestRawReaderSplitMergeStream splits and merges a concatenated stream
// of differently encoded packets, and checks tags, offsets and headers.
func TestRawReaderSplitMergeStream(t *testing.T) {
	samples := rawTestSamples()
	order := []string{"old-1byte", "old-2byte", "old-4byte", "new-2byte", "new-5byte", "new-partial", "unknown-tag"}
	var stream []byte
	for _, name := range order {
		stream = append(stream, samples[name]...)
	}
	out, packets := splitMerge(t, stream)
	if !bytes.Equal(out, stream) {
		t.Fatalf("stream split+merge mismatch:\ngot  %x\nwant %x", out, stream)
	}
	if len(packets) != len(order) {
		t.Fatalf("got %d packets, want %d", len(packets), len(order))
	}
	wantTags := []uint8{13, 13, 13, 13, 13, 13, 60}
	offset := int64(0)
	for i, pkt := range packets {
		if pkt.Tag != wantTags[i] {
			t.Errorf("packet %d: got tag %d, want %d", i, pkt.Tag, wantTags[i])
		}
		if pkt.Offset != offset {
			t.Errorf("packet %d: got offset %d, want %d", i, pkt.Offset, offset)
		}
		if pkt.Seq != uint64(i) {
			t.Errorf("packet %d: got seq %d", i, pkt.Seq)
		}
		headerLen := int64(len(samples[order[i]]) - 200)
		if int64(len(pkt.Header)) > headerLen {
			t.Errorf("packet %d: header longer than packet", i)
		}
		if !bytes.Equal(pkt.Header, stream[offset:offset+int64(len(pkt.Header))]) {
			t.Errorf("packet %d: header %x does not match stream bytes", i, pkt.Header)
		}
		offset += int64(len(samples[order[i]]))
	}
	// The unknown tag 60 packet must not be skipped and must keep its
	// contents intact.
	if packets[len(packets)-1].Tag != 60 {
		t.Fatalf("unknown-tag packet was skipped")
	}
	rr := NewRawReader(bytes.NewReader(samples["unknown-tag"]))
	unknown, err := rr.Next()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(unknown.Contents())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, rawTestContents()) {
		t.Errorf("unknown-tag packet contents corrupted")
	}
}

// TestRawReaderIndeterminate documents that an old-format
// indeterminate-length packet consumes everything up to EOF: no packet
// boundary can be determined after it.
func TestRawReaderIndeterminate(t *testing.T) {
	samples := rawTestSamples()
	// Append a full second packet after the indeterminate one: it is
	// swallowed by the first packet's body.
	stream := append(samples["old-indeterminate"], samples["new-2byte"]...)
	out, packets := splitMerge(t, stream)
	if len(packets) != 1 {
		t.Fatalf("got %d packets, want 1", len(packets))
	}
	pkt := packets[0]
	if !pkt.Indeterminate || pkt.Length != -1 {
		t.Errorf("got indeterminate=%v length=%d", pkt.Indeterminate, pkt.Length)
	}
	if !bytes.Equal(out, stream) {
		t.Errorf("indeterminate split+merge mismatch")
	}
}

// byteCountingReader counts the bytes actually read from the source.
type byteCountingReader struct {
	r io.Reader
	n int
}

func (c *byteCountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestRawReaderHeaderOnlyRead proves with a counting reader that reading
// the first packet's metadata consumes only the header bytes: no
// subsequent content is pulled into memory.
func TestRawReaderHeaderOnlyRead(t *testing.T) {
	samples := rawTestSamples()
	stream := append(samples["old-1byte"], samples["new-2byte"]...)
	cr := &byteCountingReader{r: bytes.NewReader(stream)}
	rr := NewRawReader(cr)

	pkt, err := rr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if cr.n != 2 {
		t.Errorf("after Next: %d bytes read, want 2 (header only)", cr.n)
	}
	if pkt.Tag != 13 || pkt.Offset != 0 || pkt.Length != 200 {
		t.Errorf("got tag=%d offset=%d length=%d", pkt.Tag, pkt.Offset, pkt.Length)
	}
	if !bytes.Equal(pkt.Header, []byte{0xB4, 0xC8}) {
		t.Errorf("got header %x", pkt.Header)
	}

	// Streaming consumption pulls content on demand only.
	if _, err := io.CopyN(io.Discard, pkt.Contents(), 10); err != nil {
		t.Fatal(err)
	}
	if cr.n != 12 {
		t.Errorf("after reading 10 content bytes: %d bytes read, want 12", cr.n)
	}
	if n, err := pkt.Skip(); err != nil || n != 190 {
		t.Errorf("Skip() = %d, %v; want 190, nil", n, err)
	}
	if cr.n != 202 {
		t.Errorf("after Skip: %d bytes read, want 202", cr.n)
	}

	pkt2, err := rr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if pkt2.Offset != 202 || pkt2.Seq != 1 {
		t.Errorf("packet 2: got offset=%d seq=%d", pkt2.Offset, pkt2.Seq)
	}
	if cr.n != 205 {
		t.Errorf("after second Next: %d bytes read, want 205", cr.n)
	}
	if _, err := pkt2.Skip(); err != nil {
		t.Fatal(err)
	}
	if _, err := rr.Next(); err != io.EOF {
		t.Errorf("final Next: got %v, want io.EOF", err)
	}
}

// TestRawReaderTruncated checks that truncated headers and bodies are
// reported with the packet number and raw offset, and that no seemingly
// complete packet is produced.
func TestRawReaderTruncated(t *testing.T) {
	// Clean EOF on an empty stream is not an error.
	if _, err := NewRawReader(bytes.NewReader(nil)).Next(); err != io.EOF {
		t.Errorf("empty stream: got %v, want io.EOF", err)
	}

	// Truncated header: two-octet length missing its second byte.
	rr := NewRawReader(bytes.NewReader([]byte{0xCD, 0xC0}))
	pkt, err := rr.Next()
	if pkt != nil {
		t.Errorf("truncated header: got non-nil packet")
	}
	var rpe *RawPacketError
	if !errors.As(err, &rpe) {
		t.Fatalf("truncated header: got %T, want *RawPacketError", err)
	}
	if rpe.Seq != 0 || rpe.Offset != 0 {
		t.Errorf("got seq=%d offset=%d, want 0/0", rpe.Seq, rpe.Offset)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("got %v, want io.ErrUnexpectedEOF", err)
	}

	// Truncated body: 200-byte body announced, 100 bytes present.
	truncated := append([]byte{0xB4, 0xC8}, rawTestContents()[:100]...)
	rr = NewRawReader(bytes.NewReader(truncated))
	pkt, err = rr.Next()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, err = pkt.CopyTo(&out)
	if !errors.As(err, &rpe) {
		t.Fatalf("truncated body: got %v (%T), want *RawPacketError", err, err)
	}
	if rpe.Seq != 0 || rpe.Offset != 0 {
		t.Errorf("got seq=%d offset=%d, want 0/0", rpe.Seq, rpe.Offset)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("got %v, want io.ErrUnexpectedEOF", err)
	}
	// The stream position is unknown after a truncated body: the error
	// is sticky and no further packet is fabricated.
	if _, nextErr := rr.Next(); nextErr != err {
		t.Errorf("Next after truncation: got %v, want sticky %v", nextErr, err)
	}

	// Truncation of the second packet reports its number and offset.
	samples := rawTestSamples()
	stream := append(samples["old-1byte"], 0xCD)
	rr = NewRawReader(bytes.NewReader(stream))
	pkt, err = rr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pkt.Skip(); err != nil {
		t.Fatal(err)
	}
	_, err = rr.Next()
	if !errors.As(err, &rpe) {
		t.Fatalf("truncated second packet: got %v, want *RawPacketError", err)
	}
	if rpe.Seq != 1 || rpe.Offset != 202 {
		t.Errorf("got seq=%d offset=%d, want 1/202", rpe.Seq, rpe.Offset)
	}
}

// TestRawReaderUnconsumedBody ensures Next refuses to silently advance
// past a packet whose body has not been consumed.
func TestRawReaderUnconsumedBody(t *testing.T) {
	samples := rawTestSamples()
	stream := append(samples["old-1byte"], samples["old-1byte"]...)
	rr := NewRawReader(bytes.NewReader(stream))
	pkt, err := rr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rr.Next(); err == nil {
		t.Fatal("Next with unconsumed body: got nil error")
	} else {
		var rpe *RawPacketError
		if !errors.As(err, &rpe) || rpe.Seq != 0 || rpe.Offset != 0 {
			t.Errorf("got %v, want RawPacketError seq=0 offset=0", err)
		}
	}
	// After explicitly skipping the body, Next works again.
	if n, err := pkt.Skip(); err != nil || n != 200 {
		t.Fatalf("Skip() = %d, %v", n, err)
	}
	pkt, err = rr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Seq != 1 || pkt.Offset != 202 {
		t.Errorf("got seq=%d offset=%d, want 1/202", pkt.Seq, pkt.Offset)
	}
	if _, err := pkt.Skip(); err != nil {
		t.Fatal(err)
	}
}

// TestRawReaderPartialSegments checks that every partial-body segment's
// raw length bytes are preserved, both when driving segment-by-segment
// and when streaming the contents transparently.
func TestRawReaderPartialSegments(t *testing.T) {
	sample := rawTestSamples()["new-partial"]

	// Segment-driven consumption.
	rr := NewRawReader(bytes.NewReader(sample))
	pkt, err := rr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !pkt.Partial || pkt.Length != -1 {
		t.Fatalf("got partial=%v length=%d", pkt.Partial, pkt.Length)
	}
	if !bytes.Equal(pkt.Header, []byte{0xCD, 0xE7}) {
		t.Errorf("got header %x, want cd e7", pkt.Header)
	}
	var content bytes.Buffer
	var segments []RawSegment
	for {
		seg, err := pkt.NextSegment()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		segments = append(segments, *seg)
		if _, err := io.CopyN(&content, pkt.Contents(), seg.Length); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(content.Bytes(), rawTestContents()) {
		t.Errorf("partial content mismatch")
	}
	wantLengths := []int64{128, 64, 8}
	wantLengthBytes := [][]byte{{0xE7}, {0xE6}, {0x08}}
	if len(segments) != 3 {
		t.Fatalf("got %d segments, want 3", len(segments))
	}
	for i, seg := range segments {
		if seg.Length != wantLengths[i] {
			t.Errorf("segment %d: got length %d, want %d", i, seg.Length, wantLengths[i])
		}
		if !bytes.Equal(seg.LengthBytes, wantLengthBytes[i]) {
			t.Errorf("segment %d: got length bytes %x, want %x", i, seg.LengthBytes, wantLengthBytes[i])
		}
		if seg.Final != (i == 2) {
			t.Errorf("segment %d: got final=%v", i, seg.Final)
		}
	}

	// Transparent streaming strips the length octets but records the
	// segments; CopyTo still reproduces the original encoding.
	rr = NewRawReader(bytes.NewReader(sample))
	pkt, err = rr.Next()
	if err != nil {
		t.Fatal(err)
	}
	streamed, err := io.ReadAll(pkt.Contents())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(streamed, rawTestContents()) {
		t.Errorf("streamed content mismatch")
	}
	if len(pkt.Segments) != 3 {
		t.Fatalf("got %d recorded segments, want 3", len(pkt.Segments))
	}

	out, _ := splitMerge(t, sample)
	if !bytes.Equal(out, sample) {
		t.Errorf("partial split+merge mismatch:\ngot  %x\nwant %x", out, sample)
	}
}

// TestRawReaderZeroLength checks that an empty definite-length packet
// does not require explicit consumption before the next Next call.
func TestRawReaderZeroLength(t *testing.T) {
	stream := []byte{0xC2, 0x00, 0xC2, 0x00} // two empty signature packets
	out, packets := splitMerge(t, stream)
	if len(packets) != 2 {
		t.Fatalf("got %d packets, want 2", len(packets))
	}
	if !bytes.Equal(out, stream) {
		t.Errorf("zero-length split+merge mismatch")
	}
	if packets[0].Length != 0 || packets[1].Offset != 2 {
		t.Errorf("got length=%d offset=%d", packets[0].Length, packets[1].Offset)
	}
}
