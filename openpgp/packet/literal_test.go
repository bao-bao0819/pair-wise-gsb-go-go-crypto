// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"io"
	"testing"
)

// closeTrackingWriter records whether Close was called.
type closeTrackingWriter struct {
	bytes.Buffer
	closed bool
}

func (c *closeTrackingWriter) Close() error {
	c.closed = true
	return nil
}

func TestSerializeLiteralChunkedDoesNotCloseUnderlying(t *testing.T) {
	buf := new(closeTrackingWriter)

	body, err := SerializeLiteralChunked(buf, true, "file.bin", 42, 512)
	if err != nil {
		t.Fatal(err)
	}

	const length = 513
	if _, err := body.Write(pattern(length)); err != nil {
		t.Fatal(err)
	}
	if err := body.Finish(); err != nil {
		t.Fatal(err)
	}
	if buf.closed {
		t.Fatal("Finish closed the underlying writer")
	}

	p, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	lit, ok := p.(*LiteralData)
	if !ok {
		t.Fatalf("got %T, want *LiteralData", p)
	}
	if !lit.IsBinary || lit.Format != 'b' {
		t.Errorf("bad format: %q", lit.Format)
	}
	if lit.FileName != "file.bin" {
		t.Errorf("bad file name: %q", lit.FileName)
	}
	if lit.Time != 42 {
		t.Errorf("bad time: %d", lit.Time)
	}
	got, err := io.ReadAll(lit.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pattern(length)) {
		t.Errorf("literal body mismatch (got %d bytes)", len(got))
	}
}

func TestSerializeLiteralChunkedBoundaries(t *testing.T) {
	const chunkSize = 512
	for _, length := range []int{
		0, 1, 191, 192, 193, 511, 512, 513,
		chunkSize - 1, chunkSize, chunkSize + 1,
		2*chunkSize - 1, 2 * chunkSize, 2*chunkSize + 1,
	} {
		buf := bytes.NewBuffer(nil)
		body, err := SerializeLiteralChunked(buf, false, "", 0, chunkSize)
		if err != nil {
			t.Fatalf("length=%d: %s", length, err)
		}
		want := pattern(length)
		if _, err := body.Write(want); err != nil {
			t.Fatalf("length=%d: %s", length, err)
		}
		if err := body.Finish(); err != nil {
			t.Fatalf("length=%d: %s", length, err)
		}

		p, err := Read(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Errorf("length=%d: read packet: %s", length, err)
			continue
		}
		lit := p.(*LiteralData)
		got, err := io.ReadAll(lit.Body)
		if err != nil {
			t.Errorf("length=%d: read body: %s", length, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("length=%d: body mismatch", length)
		}
	}
}

func TestSerializeLiteralClosesUnderlying(t *testing.T) {
	buf := new(closeTrackingWriter)

	plaintext, err := SerializeLiteral(buf, true, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(plaintext, "data"); err != nil {
		t.Fatal(err)
	}
	if err := plaintext.Close(); err != nil {
		t.Fatal(err)
	}
	if !buf.closed {
		t.Fatal("legacy SerializeLiteral Close did not close the underlying writer")
	}

	p, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	lit := p.(*LiteralData)
	got, err := io.ReadAll(lit.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Errorf("got %q, want %q", got, "data")
	}
}

func TestSerializeLiteralChunkedLargeSingleWrite(t *testing.T) {
	// Simulates an upload service handing tens of MB to a single Write.
	const (
		chunkSize = 512
		total     = 20 * 1024 * 1024
	)
	encoded := bytes.NewBuffer(nil)

	body, err := SerializeLiteralChunked(encoded, true, "_CONSOLE", 0, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	large := make([]byte, total)
	for i := range large {
		large[i] = byte(i)
	}
	n, err := body.Write(large)
	if err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Errorf("Write accepted %d of %d body bytes", n, total)
	}
	if cap(body.buf) != chunkSize {
		t.Errorf("residential buffer cap=%d, want bounded %d", cap(body.buf), chunkSize)
	}
	if err := body.Finish(); err != nil {
		t.Fatal(err)
	}

	// Read the packet back through the existing streaming reader and verify
	// every byte without materializing a second full-size copy.
	p, err := Read(encoded)
	if err != nil {
		t.Fatal(err)
	}
	lit := p.(*LiteralData)
	buf := make([]byte, 4096)
	var offset int
	for {
		n, err := lit.Body.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i] != large[offset+i] {
				t.Fatalf("byte %d mismatch", offset+i)
			}
		}
		offset += n
		if err == io.EOF {
			break
		}
		if err != nil && n == 0 {
			t.Fatal(err)
		}
	}
	if offset != total {
		t.Errorf("read back %d bytes, want %d", offset, total)
	}
}
