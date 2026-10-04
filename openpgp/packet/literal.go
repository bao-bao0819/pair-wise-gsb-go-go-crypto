// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"io"
)

// LiteralData represents an encrypted file. See RFC 4880, section 5.9.
type LiteralData struct {
	Format   uint8
	IsBinary bool
	FileName string
	Time     uint32 // Unix epoch time. Either creation time or modification time. 0 means undefined.
	Body     io.Reader
}

// ForEyesOnly returns whether the contents of the LiteralData have been marked
// as especially sensitive.
func (l *LiteralData) ForEyesOnly() bool {
	return l.FileName == "_CONSOLE"
}

func (l *LiteralData) parse(r io.Reader) (err error) {
	var buf [256]byte

	_, err = readFull(r, buf[:2])
	if err != nil {
		return
	}

	l.Format = buf[0]
	l.IsBinary = l.Format == 'b'
	fileNameLen := int(buf[1])

	_, err = readFull(r, buf[:fileNameLen])
	if err != nil {
		return
	}

	l.FileName = string(buf[:fileNameLen])

	_, err = readFull(r, buf[:4])
	if err != nil {
		return
	}

	l.Time = binary.BigEndian.Uint32(buf[:4])
	l.Body = r
	return
}

// SerializeLiteral serializes a literal data packet to w and returns a
// WriteCloser to which the data itself can be written and which MUST be closed
// on completion. The fileName is truncated to 255 bytes.
//
// The body is streamed in bounded-size partial body chunks. Closing the
// returned writer terminates the literal packet and also closes w, preserving
// the historical behavior of this entry point. To terminate the literal
// packet without closing w, use SerializeLiteralChunked instead.
func SerializeLiteral(w io.WriteCloser, isBinary bool, fileName string, time uint32) (plaintext io.WriteCloser, err error) {
	body, err := serializeLiteralBody(w, isBinary, fileName, time, defaultLiteralChunkSize)
	if err != nil {
		return nil, err
	}
	return &partialBodyWriteCloser{body: body, closer: w}, nil
}

// SerializeLiteralChunked serializes a literal data packet to w and returns a
// *PartialLengthWriter to which the packet body is written in partial chunks
// of chunkSize bytes. The returned writer's Finish method terminates the
// literal packet but never closes w; the caller remains responsible for
// closing the underlying writer. The fileName is truncated to 255 bytes.
//
// chunkSize must be a power of two between 512 and 2^30, as required for
// OpenPGP partial body lengths. The amount of body data buffered by the
// returned writer never exceeds chunkSize bytes.
func SerializeLiteralChunked(w io.Writer, isBinary bool, fileName string, time uint32, chunkSize int) (plaintext *PartialLengthWriter, err error) {
	return serializeLiteralBody(w, isBinary, fileName, time, chunkSize)
}

func serializeLiteralBody(w io.Writer, isBinary bool, fileName string, time uint32, chunkSize int) (plaintext *PartialLengthWriter, err error) {
	var buf [4]byte
	buf[0] = 'b'
	if !isBinary {
		buf[0] = 'u'
	}
	if len(fileName) > 255 {
		fileName = fileName[:255]
	}
	buf[1] = byte(len(fileName))

	inner, err := serializeStreamHeaderChunked(w, packetTypeLiteralData, chunkSize)
	if err != nil {
		return
	}

	_, err = inner.Write(buf[:2])
	if err != nil {
		return
	}
	_, err = inner.Write([]byte(fileName))
	if err != nil {
		return
	}
	binary.BigEndian.PutUint32(buf[:], time)
	_, err = inner.Write(buf[:])
	if err != nil {
		return
	}

	plaintext = inner
	return
}
