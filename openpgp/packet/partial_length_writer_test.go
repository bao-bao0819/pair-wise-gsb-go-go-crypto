// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestNewPartialLengthWriterInvalidChunkSize(t *testing.T) {
	for _, chunkSize := range []int{0, 1, 256, 511, 513, 1000, 1023, (1 << 30) * 2, -1} {
		if _, err := NewPartialLengthWriter(io.Discard, chunkSize); err == nil {
			t.Errorf("chunkSize %d: expected error, got nil", chunkSize)
		}
	}

	for power := uint(9); power <= 30; power++ {
		if _, err := NewPartialLengthWriter(io.Discard, 1<<power); err != nil {
			t.Errorf("chunkSize %d: unexpected error: %s", 1<<power, err)
		}
	}
}

// failingWriter fails after a configurable number of successful bytes.
type failingWriter struct {
	remaining int
	err       error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, w.err
	}
	if len(p) <= w.remaining {
		w.remaining -= len(p)
		return len(p), nil
	}
	n := w.remaining
	w.remaining = 0
	return n, w.err
}

// shortWriter never writes more than half of the requested bytes.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	n := len(p) / 2
	return n, nil
}

// countWriter counts bytes forwarded to it without retaining them.
type countWriter struct {
	n int64
}

func (w *countWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

func TestPartialLengthWriterErrorsAreSticky(t *testing.T) {
	sentinel := errors.New("boom")

	// Underlying writer returns (0, err) on the very first header write.
	w, err := NewPartialLengthWriter(&failingWriter{remaining: 0, err: sentinel}, 512)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0x42}, 1024)
	n, err := w.Write(data)
	if n != 0 || !errors.Is(err, sentinel) {
		t.Errorf("first Write got (n=%d, err=%v), want (0, %v)", n, err, sentinel)
	}
	if err := w.Finish(); !errors.Is(err, sentinel) {
		t.Errorf("Finish got %v, want %v", err, sentinel)
	}
	if n, err := w.Write(data); n != 0 || !errors.Is(err, sentinel) {
		t.Errorf("Write after failure got (n=%d, err=%v), want (0, %v)", n, err, sentinel)
	}

	// Underlying writer accepts some bytes, then returns n together with err.
	fw := &failingWriter{remaining: 700, err: sentinel}
	w, err = NewPartialLengthWriter(fw, 512)
	if err != nil {
		t.Fatal(err)
	}
	n, err = w.Write(data)
	if !errors.Is(err, sentinel) {
		t.Errorf("Write got err %v, want %v", err, sentinel)
	}
	if n < 0 || n > len(data) {
		t.Errorf("Write returned out-of-range n=%d", n)
	}
	if err := w.Finish(); !errors.Is(err, sentinel) {
		t.Errorf("Finish got %v, want %v", err, sentinel)
	}

	// A short write without an error is reported as ErrShortWrite and is
	// likewise sticky.
	w, err = NewPartialLengthWriter(shortWriter{}, 512)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(data); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("short Write got %v, want ErrShortWrite", err)
	}
	if err := w.Finish(); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("Finish after short write got %v, want ErrShortWrite", err)
	}
}

func TestPartialLengthWriterFinishSemantics(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w, err := NewPartialLengthWriter(buf, 512)
	if err != nil {
		t.Fatal(err)
	}

	// Repeated empty writes must not produce any partial chunks.
	for i := 0; i < 5; i++ {
		if n, err := w.Write(nil); n != 0 || err != nil {
			t.Errorf("empty Write %d got (n=%d, err=%v)", i, n, err)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("empty writes produced %d bytes of output", buf.Len())
	}

	if err := w.Finish(); err != nil {
		t.Fatalf("first Finish: %s", err)
	}
	// Repeated Finish is deterministic and produces no extra output.
	encoded := buf.Len()
	if err := w.Finish(); err != nil {
		t.Errorf("second Finish: %s", err)
	}
	if err := w.Finish(); err != nil {
		t.Errorf("third Finish: %s", err)
	}
	if buf.Len() != encoded {
		t.Errorf("repeated Finish added %d bytes", buf.Len()-encoded)
	}

	// Writing after Finish fails without emitting anything.
	if n, err := w.Write([]byte{1}); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Write after Finish got (n=%d, err=%v), want (0, ErrClosedPipe)", n, err)
	}

	// The body read back must be empty; a single zero-length final chunk.
	body, err := io.ReadAll(&partialLengthReader{bytes.NewReader(buf.Bytes()), 0, true})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Errorf("got %d body bytes, want 0", len(body))
	}
}

func TestPartialLengthWriterReturnedNExcludesHeaders(t *testing.T) {
	const chunkSize = 512
	cw := new(countWriter)
	w, err := NewPartialLengthWriter(cw, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		chunk []byte
		n     int
	}{
		{make([]byte, 100), 100},
		{make([]byte, 412), 412}, // completes the first 512 byte chunk
		{make([]byte, 512), 512}, // one full chunk straight through
		{make([]byte, 1024), 1024},
		{make([]byte, 1), 1},
		{nil, 0},
	}
	var written int
	for i, tc := range cases {
		n, err := w.Write(tc.chunk)
		if err != nil {
			t.Fatalf("case %d: %s", i, err)
		}
		if n != tc.n {
			t.Errorf("case %d: n=%d, want %d", i, n, tc.n)
		}
		written += n
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}

	// 2049 body bytes, 3 full partial chunks and a 513 byte final chunk.
	if written != 2049 {
		t.Errorf("accepted %d body bytes, want 2049", written)
	}
	if cw.n != 2049+3+2 {
		t.Errorf("encoded stream is %d bytes, want %d", cw.n, 2049+3+2)
	}
}

// TestPartialLengthWriterBufferBounded verifies with a non-storing counting
// writer that streaming a large single Write never buffers more than the
// configured chunk size, and that the encoded stream decodes to the original
// data.
func TestPartialLengthWriterBufferBounded(t *testing.T) {
	const (
		chunkSize = 512
		total     = 10 * 1024 * 1024
	)

	w, err := NewPartialLengthWriter(io.Discard, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// One huge Write: the internal buffer capacity is fixed at chunkSize and
	// complete chunks are emitted directly from the caller's slice.
	big := make([]byte, total)
	n, err := w.Write(big)
	if err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Errorf("n=%d, want %d", n, total)
	}
	if cap(w.buf) != chunkSize {
		t.Errorf("internal buffer capacity=%d, want bounded %d", cap(w.buf), chunkSize)
	}
	if len(w.buf) != 0 {
		t.Errorf("expected no buffered remainder, got %d", len(w.buf))
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}

	// Round trip through the existing reader at boundary-adjacent sizes.
	for _, length := range []int{
		0, 1, 191, 192, 193, 511, 512, 513,
		8383, 8384, 8385,
		chunkSize - 1, chunkSize, chunkSize + 1,
		2*chunkSize - 1, 2 * chunkSize, 2*chunkSize + 1,
		100 * chunkSize,
	} {
		encoded := encodePartialBody(length, chunkSize)
		r := &partialLengthReader{bytes.NewReader(encoded), 0, true}
		got, err := io.Copy(io.Discard, r)
		if err != nil {
			t.Errorf("length=%d: read error: %s", length, err)
			continue
		}
		if got != int64(length) {
			t.Errorf("length=%d: decoded %d bytes", length, got)
		}
	}
}

// encodePartialBody produces a partial-body encoding of length zeroed bytes
// using a writer configured with the given chunk size.
func encodePartialBody(length, chunkSize int) []byte {
	buf := bytes.NewBuffer(nil)
	w, err := NewPartialLengthWriter(buf, chunkSize)
	if err != nil {
		panic(err)
	}
	if _, err := io.CopyN(w, zeroReader{}, int64(length)); err != nil {
		panic(err)
	}
	if err := w.Finish(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestPartialLengthWriterChunkBoundaries(t *testing.T) {
	for _, chunkSize := range []int{512, 1024, 4096} {
		for _, length := range []int{
			0, 1, chunkSize - 1, chunkSize, chunkSize + 1,
			2*chunkSize - 1, 2 * chunkSize, 2*chunkSize + 1,
			7*chunkSize + 3,
		} {
			want := pattern(length)
			buf := bytes.NewBuffer(nil)
			w, err := NewPartialLengthWriter(buf, chunkSize)
			if err != nil {
				t.Fatal(err)
			}

			// Exercise splitting: write in fragments of varying sizes.
			for off := 0; off < len(want); {
				frag := 1 + (off*7)%(2*chunkSize)
				if off+frag > len(want) {
					frag = len(want) - off
				}
				n, err := w.Write(want[off : off+frag])
				if n != frag || err != nil {
					t.Fatalf("chunkSize=%d length=%d off=%d: got (n=%d, err=%v)", chunkSize, length, off, n, err)
				}
				off += frag
			}
			if err := w.Finish(); err != nil {
				t.Fatalf("chunkSize=%d length=%d: %s", chunkSize, length, err)
			}

			r := &partialLengthReader{bytes.NewReader(buf.Bytes()), 0, true}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Errorf("chunkSize=%d length=%d: %s", chunkSize, length, err)
				continue
			}
			if !bytes.Equal(got, want) {
				t.Errorf("chunkSize=%d length=%d: content mismatch", chunkSize, length)
			}
		}
	}
}

// pattern returns a deterministic byte slice of length n.
func pattern(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i * 1103515245)
	}
	return p
}
