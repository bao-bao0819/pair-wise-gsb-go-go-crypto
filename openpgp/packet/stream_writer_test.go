// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

var errInjected = errors.New("injected writer failure")

// countingSink accepts arbitrary amounts of data without retaining any of the
// bytes. It only records how much was written in total and how large the
// largest single body write was.
type countingSink struct {
	total        int64
	maxBodyWrite int
	closeCount   int
}

func (c *countingSink) Write(p []byte) (int, error) {
	c.total += int64(len(p))
	if len(p) > 1 && len(p) > c.maxBodyWrite {
		c.maxBodyWrite = len(p)
	}
	return len(p), nil
}

func (c *countingSink) Close() error {
	c.closeCount++
	return nil
}

// failingBodySink fails or short-writes body writes (any write longer than a
// single length-header byte), while always accepting header bytes. It records
// how many bytes it has observed so tests can assert that no further output
// is produced after a failure.
type failingBodySink struct {
	total      int64
	bodyWrites int
	failAtBody int // 1-based body write on which (n, err) is returned
	failN      int // bytes accepted on the failing write
	shortAt    int // 1-based body write on which a short write is returned
	closeCount int
}

func (f *failingBodySink) Write(p []byte) (int, error) {
	if len(p) == 1 {
		f.total++
		return 1, nil
	}
	f.bodyWrites++
	switch {
	case f.failAtBody > 0 && f.bodyWrites == f.failAtBody:
		n := f.failN
		if n > len(p) {
			n = len(p)
		}
		f.total += int64(n)
		return n, errInjected
	case f.shortAt > 0 && f.bodyWrites == f.shortAt:
		n := len(p) - 1
		f.total += int64(n)
		return n, nil
	}
	f.total += int64(len(p))
	return len(p), nil
}

func (f *failingBodySink) Close() error {
	f.closeCount++
	return nil
}

// failAtHeaderWriter fails every write (including length headers).
type failAtHeaderWriter struct{}

func (failAtHeaderWriter) Write(p []byte) (int, error) {
	return 0, errInjected
}

func TestValidPartialChunkSize(t *testing.T) {
	for _, size := range []int{512, 1024, 4096, 1 << 20, 1 << 30} {
		if !validPartialChunkSize(size) {
			t.Errorf("size %d unexpectedly rejected", size)
		}
	}
	for _, size := range []int{0, 1, 2, 256, 511, 513, 1000, 3 << 29, 1<<30 + 1, -512} {
		if validPartialChunkSize(size) {
			t.Errorf("size %d unexpectedly accepted", size)
		}
	}
}

func TestSerializeLiteralStreamValidation(t *testing.T) {
	for _, size := range []int{0, 1, 256, 511, 513, 1023} {
		if _, err := SerializeLiteralStream(io.Discard, true, "", 0, size); err == nil {
			t.Errorf("chunk size %d: expected error, got nil", size)
		}
	}
	if _, err := SerializeLiteralStream(io.Discard, true, "", 0, 512); err != nil {
		t.Fatalf("chunk size 512: unexpected error: %s", err)
	}
}

func TestStreamWriterBoundedBuffer(t *testing.T) {
	const chunkSize = 512
	const inputSize = 10 * 1024 * 1024

	sink := &countingSink{}
	sw := newStreamWriter(sink, chunkSize)

	// Feed the whole multi-megabyte input in a single Write, mimicking an
	// upload service handing us one large buffer.
	input := bytes.Repeat([]byte{0xab}, inputSize)
	n, err := sw.Write(input)
	if err != nil {
		t.Fatalf("Write: %s", err)
	}
	if n != inputSize {
		t.Fatalf("Write returned n=%d, want %d (headers must not be counted)", n, inputSize)
	}

	// The private buffer never grew beyond the configured chunk size.
	if cap(sw.buf) != chunkSize {
		t.Errorf("buffer cap = %d, want %d", cap(sw.buf), chunkSize)
	}
	if len(sw.buf) > chunkSize {
		t.Errorf("buffered body = %d, want at most %d", len(sw.buf), chunkSize)
	}
	// The sink retained nothing and never saw a body write larger than one
	// chunk, so peak in-memory data was bounded by chunkSize even though the
	// input was many orders of magnitude larger.
	if sink.maxBodyWrite > chunkSize {
		t.Errorf("underlying writer received %d body bytes at once, want at most %d", sink.maxBodyWrite, chunkSize)
	}
	if sink.total <= inputSize {
		t.Errorf("expected length headers on top of %d body bytes, got %d", inputSize, sink.total)
	}

	if err := sw.Finish(); err != nil {
		t.Fatalf("Finish: %s", err)
	}
}

// writePattern fills a StreamWriter in variable-sized Writes with bytes whose
// value cycles with their position, so content can be verified on readback.
func writePattern(t *testing.T, sw *StreamWriter, size int) {
	t.Helper()
	p := make([]byte, size)
	for i := range p {
		p[i] = byte(i)
	}

	var off int
	sizes := []int{1, 7, 512, 513, 1, 1000}
	for i := 0; off < len(p); i++ {
		n := sizes[i%len(sizes)]
		if n > len(p)-off {
			n = len(p) - off
		}
		m, err := sw.Write(p[off : off+n])
		if err != nil {
			t.Fatalf("Write at %d: %s", off, err)
		}
		if m != n {
			t.Fatalf("Write at %d accepted %d of %d body bytes", off, m, n)
		}
		off += n
	}
}

func TestStreamWriterRoundtripBoundaryLengths(t *testing.T) {
	const chunkSize = 512
	lengths := []int{
		0, 1, 2,
		chunkSize - 1, chunkSize, chunkSize + 1,
		2*chunkSize - 1, 2 * chunkSize, 2*chunkSize + 1,
		3*chunkSize - 1, 3 * chunkSize, 3*chunkSize + 1,
		10*chunkSize - 1, 10 * chunkSize, 10*chunkSize + 1,
	}

	for _, size := range lengths {
		t.Run(fmt.Sprintf("len=%d", size), func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			sw, err := SerializeLiteralStream(buf, true, "file", 42, chunkSize)
			if err != nil {
				t.Fatalf("SerializeLiteralStream: %s", err)
			}
			writePattern(t, sw, size)
			if err := sw.Finish(); err != nil {
				t.Fatalf("Finish: %s", err)
			}

			// Read it back with the regular packet Reader.
			p, err := Read(buf)
			if err != nil {
				t.Fatalf("Read: %s", err)
			}
			lit, ok := p.(*LiteralData)
			if !ok {
				t.Fatalf("got %T, want *LiteralData", p)
			}
			if !lit.IsBinary || lit.FileName != "file" || lit.Time != 42 {
				t.Errorf("header mismatch: format=%q file=%q time=%d binary=%t", lit.Format, lit.FileName, lit.Time, lit.IsBinary)
			}
			body, err := io.ReadAll(lit.Body)
			if err != nil {
				t.Fatalf("ReadAll body: %s", err)
			}
			if len(body) != size {
				t.Fatalf("body length = %d, want %d", len(body), size)
			}
			for i := 0; i < size; i++ {
				if body[i] != byte(i) {
					t.Fatalf("byte %d = %d, want %d", i, body[i], byte(i))
				}
			}
		})
	}
}

func TestStreamWriterExactMultipleFinalChunk(t *testing.T) {
	// Regardless of whether the body divides evenly, Finish must emit a
	// legal final fixed-length chunk. Decode the raw partial encoding and
	// inspect the trailing length byte.
	for _, size := range []int{0, 512, 1024, 2048} {
		buf := bytes.NewBuffer(nil)
		sw := newStreamWriter(buf, 512)
		writePattern(t, sw, size)
		if err := sw.Finish(); err != nil {
			t.Fatalf("size %d Finish: %s", size, err)
		}

		r := &partialLengthReader{r: bytes.NewReader(buf.Bytes()), remaining: 0, isPartial: true}
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("size %d decode: %s", size, err)
		}
		if len(out) != size {
			t.Fatalf("size %d decoded %d bytes", size, len(out))
		}
		// The last byte on the wire must be a non-partial (fixed) length:
		// zero for exact multiples, otherwise the remainder (< chunkSize).
		trailing := buf.Bytes()[buf.Len()-1]
		if trailing >= 224 && trailing < 255 {
			t.Errorf("size %d ends on a partial length byte 0x%02x; want fixed-length chunk", size, trailing)
		}
	}
}

func TestStreamWriterEmptyWrites(t *testing.T) {
	sink := &countingSink{}
	sw := newStreamWriter(sink, 512)

	// Repeated empty Writes must be deterministic and must not produce any
	// output or change accepted state.
	for i := 0; i < 5; i++ {
		n, err := sw.Write(nil)
		if n != 0 || err != nil {
			t.Fatalf("empty Write #%d: n=%d err=%v", i, n, err)
		}
	}
	if sink.total != 0 {
		t.Errorf("empty writes produced %d output bytes", sink.total)
	}
	if err := sw.Finish(); err != nil {
		t.Fatalf("Finish: %s", err)
	}
	// Empty body: exactly one zero-length fixed chunk header.
	if sink.total != 1 {
		t.Errorf("empty body wrote %d bytes, want 1", sink.total)
	}
}

func TestStreamWriterRepeatedFinish(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	sw := newStreamWriter(buf, 512)
	if _, err := sw.Write(make([]byte, 600)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := sw.Finish(); err != nil {
			t.Fatalf("Finish #%d: %s", i, err)
		}
	}
	// Exactly one final fixed-length chunk for a 600-byte body.
	r := &partialLengthReader{r: bytes.NewReader(buf.Bytes()), remaining: 0, isPartial: true}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decode: %s", err)
	}
	if len(out) != 600 {
		t.Fatalf("decoded %d bytes, want 600", len(out))
	}

	// Writing after Finish is a deterministic error, not a panic or silent
	// success, and must produce no additional bytes.
	wireLen := buf.Len()
	n, err := sw.Write([]byte{1})
	if n != 0 || err == nil {
		t.Fatalf("Write after Finish: n=%d err=%v", n, err)
	}
	if buf.Len() != wireLen {
		t.Fatalf("Write after Finish emitted bytes (%d -> %d)", wireLen, buf.Len())
	}
	// The error is sticky.
	if _, err := sw.Write([]byte{1}); err == nil {
		t.Fatal("second Write after Finish unexpectedly succeeded")
	}
	if err := sw.Finish(); err == nil {
		t.Fatal("Finish after failed Write unexpectedly succeeded")
	}
}

func TestStreamWriterShortWrite(t *testing.T) {
	sink := &failingBodySink{shortAt: 2}
	sw := newStreamWriter(sink, 512)
	// The second of three full chunks is accepted short by one byte.
	n, err := sw.Write(make([]byte, 3*512))
	if err != io.ErrShortWrite {
		t.Fatalf("err = %v, want io.ErrShortWrite", err)
	}
	if n != 2*512-1 {
		t.Fatalf("n = %d, want %d accepted body bytes", n, 2*512-1)
	}

	// After the short write the error sticks and nothing more is emitted.
	before := sink.total
	if _, err := sw.Write(make([]byte, 512)); err != io.ErrShortWrite {
		t.Fatalf("sticky err = %v, want io.ErrShortWrite", err)
	}
	if sink.total != before {
		t.Fatalf("wrote %d extra bytes after failure", sink.total-before)
	}
	if err := sw.Finish(); err != io.ErrShortWrite {
		t.Fatalf("Finish err = %v, want io.ErrShortWrite", err)
	}
}

func TestStreamWriterWriteReturnsNAndErr(t *testing.T) {
	// The failing write accepts 100 bytes of a 512-byte chunk alongside an
	// error. n must report those 100 accepted body bytes; headers are never
	// counted.
	sink := &failingBodySink{failAtBody: 1, failN: 100}
	sw := newStreamWriter(sink, 512)
	n, err := sw.Write(make([]byte, 512))
	if err != errInjected {
		t.Fatalf("err = %v, want %v", err, errInjected)
	}
	if n != 100 {
		t.Fatalf("n = %d, want 100", n)
	}
	if err := sw.Finish(); err != errInjected {
		t.Fatalf("Finish did not preserve first error: %v", err)
	}
}

func TestStreamWriterFailureEmitsNoTail(t *testing.T) {
	sink := &failingBodySink{failAtBody: 1, failN: 0}
	sw := newStreamWriter(sink, 512)
	if _, err := sw.Write(make([]byte, 512)); err != errInjected {
		t.Fatalf("err = %v", err)
	}

	// Finish must not append a deceptively valid final fixed-length chunk
	// after a previous failure.
	wireBefore := sink.total
	if err := sw.Finish(); err != errInjected {
		t.Fatalf("Finish err = %v, want %v", err, errInjected)
	}
	if sink.total != wireBefore {
		t.Fatalf("Finish emitted %d extra bytes after failure", sink.total-wireBefore)
	}
}

func TestStreamWriterBufferedTailFailureN(t *testing.T) {
	// First buffer 10 bytes, then complete the first chunk in a second Write.
	// When the single chunk write fails after accepting 105 bytes, 5 of those
	// bytes belong to the current Write (105 - 10 buffered), and that is what
	// n must report.
	sink := &failingBodySink{failAtBody: 1, failN: 105}
	sw := newStreamWriter(sink, 512)
	if n, err := sw.Write(make([]byte, 10)); err != nil || n != 10 {
		t.Fatalf("buffering Write: n=%d err=%v", n, err)
	}
	n, err := sw.Write(make([]byte, 502))
	if err != errInjected {
		t.Fatalf("err = %v, want %v", err, errInjected)
	}
	if n != 95 {
		t.Fatalf("n = %d, want 95 (105 accepted minus 10 previously buffered)", n)
	}
}

func TestStreamWriterHeaderFailure(t *testing.T) {
	// A length-header write failure must surface immediately and stick.
	sw := newStreamWriter(failAtHeaderWriter{}, 512)
	if _, err := sw.Write(make([]byte, 512)); err != errInjected {
		t.Fatalf("err = %v, want %v", err, errInjected)
	}
	if err := sw.Finish(); err != errInjected {
		t.Fatalf("Finish err = %v, want %v", err, errInjected)
	}
}

func TestStreamWriterFinishDoesNotCloseUnderlying(t *testing.T) {
	sink := &countingSink{}
	sw := newStreamWriter(sink, 512)
	if _, err := sw.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := sw.Finish(); err != nil {
		t.Fatalf("Finish: %s", err)
	}
	if sink.closeCount != 0 {
		t.Fatalf("Finish closed the underlying writer %d times", sink.closeCount)
	}
	// Close finishes (already done) and closes exactly once.
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %s", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("second Close: %s", err)
	}
	if sink.closeCount != 1 {
		t.Fatalf("underlying Close count = %d, want 1", sink.closeCount)
	}
}

func TestStreamWriterCloseBeforeFailureDoesNotClose(t *testing.T) {
	sink := &failingBodySink{failAtBody: 1, failN: 0}
	sw := newStreamWriter(sink, 512)
	if _, err := sw.Write(make([]byte, 512)); err != errInjected {
		t.Fatalf("err = %v", err)
	}
	if err := sw.Close(); err != errInjected {
		t.Fatalf("Close err = %v, want %v", err, errInjected)
	}
	if sink.closeCount != 0 {
		t.Fatalf("underlying writer was closed despite failed Finish")
	}
}
