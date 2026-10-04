// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
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
func SerializeLiteral(w io.WriteCloser, isBinary bool, fileName string, time uint32) (plaintext io.WriteCloser, err error) {
	var buf [4]byte
	buf[0] = 'b'
	if !isBinary {
		buf[0] = 'u'
	}
	if len(fileName) > 255 {
		fileName = fileName[:255]
	}
	buf[1] = byte(len(fileName))

	inner, err := serializeStreamHeader(w, packetTypeLiteralData)
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

// SerializeLiteralStream serializes a literal data packet header to w and
// returns a *StreamWriter to which the packet body is written using OpenPGP
// partial body lengths of at most chunkSize bytes.
//
// Unlike SerializeLiteral, the in-memory buffer is bounded by chunkSize no
// matter how large a single Write is, so callers can stream multi-megabyte
// (or larger) uploads without the buffer growing with the input.
//
// chunkSize must be a power of two between 512 and 2^30 bytes (see RFC 4880,
// section 4.2.2.4); any other value results in an error.
//
// The returned *StreamWriter distinguishes finishing the current packet from
// closing w: Finish writes the legal final fixed-length chunk (even when the
// body length is an exact multiple of chunkSize) but does not close w, so a
// caller that keeps writing further packets can use Finish and then continue
// on the same writer. Close is equivalent to Finish followed by closing w
// when w implements io.Closer. The caller remains responsible for closing w
// after Finish. The fileName is truncated to 255 bytes.
func SerializeLiteralStream(w io.Writer, isBinary bool, fileName string, time uint32, chunkSize int) (plaintext *StreamWriter, err error) {
	if !validPartialChunkSize(chunkSize) {
		return nil, errors.InvalidArgumentError("invalid partial chunk size")
	}

	var header [6]byte
	if isBinary {
		header[0] = 'b'
	} else {
		header[0] = 'u'
	}
	if len(fileName) > 255 {
		fileName = fileName[:255]
	}
	header[1] = byte(len(fileName))
	binary.BigEndian.PutUint32(header[2:], time)

	if err = serializeType(w, packetTypeLiteralData); err != nil {
		return nil, err
	}

	sw := newStreamWriter(w, chunkSize)
	// The literal data header (format, file name and time) is part of the
	// packet body and is accounted for by the returned writer.
	if _, err = sw.Write(header[:2]); err != nil {
		return nil, err
	}
	if _, err = sw.Write([]byte(fileName)); err != nil {
		return nil, err
	}
	if _, err = sw.Write(header[2:]); err != nil {
		return nil, err
	}
	return sw, nil
}
