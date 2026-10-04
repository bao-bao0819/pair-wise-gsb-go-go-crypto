// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

const (
	// minPartialBodyChunkSize is the smallest partial body chunk length that
	// may start a partial data packet. See RFC 9580, section 4.2.2.4.
	minPartialBodyChunkSize = 1 << 9  // 512 bytes
	maxPartialBodyChunkSize = 1 << 30 // 1 GiB
)

// PartialLengthWriter writes a packet body using OpenPGP partial body length
// headers (RFC 9580, section 4.2.2.4) using a fixed, caller-selected chunk
// size. Complete chunks, each prefixed with a single partial length byte, are
// flushed to the underlying writer as soon as they fill up, so the amount of
// body data held in memory never exceeds the configured chunk size.
//
// Finish writes the final, fixed-length body chunk. The final chunk is always
// emitted, even when no body data was written or the total body length is an
// exact multiple of the chunk size. Finish is idempotent: the first call
// reports the outcome, and subsequent calls report the same result.
//
// PartialLengthWriter never closes the underlying writer; use Close on the
// writer passed to its constructor when the underlying stream should be
// closed as well. After the first failure, the first error is retained and
// every subsequent Write and Finish call returns it without producing any
// additional output, so a failed packet never gains a trailing chunk that
// could be mistaken for a successfully terminated packet.
//
// The n returned by Write counts body bytes accepted from the caller;
// encoding header bytes are not counted.
type PartialLengthWriter struct {
	w          io.Writer
	chunkSize  int
	buf        []byte
	lengthByte byte
	err        error
	finished   bool
}

// NewPartialLengthWriter returns a PartialLengthWriter that streams body data
// to w using partial body chunks of chunkSize bytes. chunkSize must be a power
// of two between 512 and 2^30, as required for OpenPGP partial body lengths.
func NewPartialLengthWriter(w io.Writer, chunkSize int) (*PartialLengthWriter, error) {
	if chunkSize < minPartialBodyChunkSize || chunkSize > maxPartialBodyChunkSize {
		return nil, errors.InvalidArgumentError("partial body chunk size out of range")
	}
	if chunkSize&(chunkSize-1) != 0 {
		return nil, errors.InvalidArgumentError("partial body chunk size must be a power of two")
	}

	var power uint
	for size := chunkSize; size > 1; size >>= 1 {
		power++
	}

	return &PartialLengthWriter{
		w:          w,
		chunkSize:  chunkSize,
		buf:        make([]byte, 0, chunkSize),
		lengthByte: byte(224 + power),
	}, nil
}

// Write writes body data to the stream. Data is buffered up to the configured
// chunk size and flushed in complete partial chunks. It returns the number of
// body bytes accepted from p, excluding encoding headers.
func (w *PartialLengthWriter) Write(p []byte) (n int, err error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.finished {
		w.err = io.ErrClosedPipe
		return 0, w.err
	}

	for len(p) > 0 {
		if len(w.buf) == 0 && len(p) >= w.chunkSize {
			if err := w.emitChunk(p[:w.chunkSize]); err != nil {
				w.err = err
				return n, err
			}
			n += w.chunkSize
			p = p[w.chunkSize:]
			continue
		}

		copied := copy(w.buf[len(w.buf):w.chunkSize], p)
		w.buf = w.buf[:len(w.buf)+copied]
		n += copied
		p = p[copied:]

		if len(w.buf) == w.chunkSize {
			if err := w.emitChunk(w.buf); err != nil {
				w.buf = w.buf[:0]
				w.err = err
				return n, err
			}
			w.buf = w.buf[:0]
		}
	}
	return n, nil
}

// Finish terminates the packet by writing the final fixed-length body chunk,
// which contains any buffered body data. It never closes the underlying
// writer. Calling Finish more than once returns the result of the first call.
func (w *PartialLengthWriter) Finish() error {
	if w.err != nil {
		return w.err
	}
	if w.finished {
		return nil
	}

	err := serializeFixedLength(w.w, len(w.buf))
	if err == nil {
		err = writeFull(w.w, w.buf)
	}
	if err != nil {
		w.err = err
		return err
	}

	w.finished = true
	w.buf = w.buf[:0]
	return nil
}

// emitChunk writes a single partial body chunk of exactly w.chunkSize body
// bytes, prefixed by its partial length byte.
func (w *PartialLengthWriter) emitChunk(chunk []byte) error {
	var header [1]byte
	header[0] = w.lengthByte
	if err := writeFull(w.w, header[:]); err != nil {
		return err
	}
	return writeFull(w.w, chunk)
}

// writeFull writes all of p to w. A short write is reported as
// io.ErrShortWrite, matching the behavior of io.Writer contract violations.
func writeFull(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

// serializeFixedLength writes a fixed (non-partial) OpenPGP body length to w
// using the 1, 2, or 5 byte encoding of RFC 9580, section 4.2.2.1, treating a
// short write as an error.
func serializeFixedLength(w io.Writer, length int) error {
	var buf [5]byte
	var n int
	switch {
	case length < 192:
		buf[0] = byte(length)
		n = 1
	case length < 8384:
		encoded := length - 192
		buf[0] = 192 + byte(encoded>>8)
		buf[1] = byte(encoded)
		n = 2
	default:
		buf[0] = 255
		buf[1] = byte(length >> 24)
		buf[2] = byte(length >> 16)
		buf[3] = byte(length >> 8)
		buf[4] = byte(length)
		n = 5
	}
	return writeFull(w, buf[:n])
}

// serializeStreamHeaderChunked writes an OpenPGP packet tag to w followed by a
// PartialLengthWriter with the given chunk size for the packet body. The
// returned writer's Finish terminates the packet without closing w.
func serializeStreamHeaderChunked(w io.Writer, ptype packetType, chunkSize int) (*PartialLengthWriter, error) {
	if err := serializeType(w, ptype); err != nil {
		return nil, err
	}
	return NewPartialLengthWriter(w, chunkSize)
}

// defaultLiteralChunkSize is the chunk size used when serializing a literal
// packet through the legacy, close-underlying-writer entry point.
const defaultLiteralChunkSize = 1 << 20 // 1 MiB

// partialBodyWriteCloser adapts a PartialLengthWriter to the io.WriteCloser
// returned by legacy streaming entry points: Close terminates the packet and
// then closes the underlying writer.
type partialBodyWriteCloser struct {
	body   *PartialLengthWriter
	closer io.Closer
}

func (c *partialBodyWriteCloser) Write(p []byte) (int, error) {
	return c.body.Write(p)
}

func (c *partialBodyWriteCloser) Close() error {
	if err := c.body.Finish(); err != nil {
		return err
	}
	return c.closer.Close()
}
