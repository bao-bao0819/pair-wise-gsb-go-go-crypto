// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"io"

	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
)

// RawPacket is a single OpenPGP packet read by RawReader. Unlike OpaquePacket,
// which re-encodes the header when serializing, RawPacket preserves the exact
// header bytes found on the wire, including every partial-body length octet.
//
// RawPacket is itself an io.Reader over the bounded packet body. Reads never
// cross the packet boundary. Partial-body length octets are not stripped:
// they are yielded verbatim between the data chunks, so Header followed by a
// full read of the body reconstructs the exact on-wire packet bytes.
//
// The caller decides what to do with the body: copy it with WriteTo, stream
// it through Read, or skip it with Discard. The current packet must be fully
// consumed, copied or discarded before RawReader.Next is called again; Next
// never reads into the following packet behind the caller's back.
type RawPacket struct {
	// Tag is the packet tag (0-63). Old-format tags use the same numbering
	// as new-format tags.
	Tag uint8
	// StartOffset is the absolute offset of the first header byte.
	StartOffset int64
	// Header is the exact unmodified header on the wire: tag byte plus
	// length bytes. For a partial packet it holds the tag byte and the first
	// partial-body length octet; later chunk length octets are delivered
	// through the body stream.
	Header []byte
	// FixedLength is the declared definite body length, or -1 for partial
	// packets and old-format indeterminate-length packets.
	FixedLength int64
	// Partial reports whether the body uses partial body length encoding
	// (RFC 4880, section 4.2.2.4). This value never changes while reading.
	Partial bool
	// Consumed counts raw body bytes already yielded through Read, WriteTo
	// or Discard, including partial-body length octets. It is the offset of
	// the next body byte relative to the end of Header.
	Consumed int64

	r *RawReader

	done          bool
	indeterminate bool
	inPartial     bool

	// remaining bytes in the current definite body or partial data chunk.
	remaining int64
	// pending raw bytes (chunk length octets) to emit before chunk data.
	pending []byte
}

// Read implements io.Reader for the bounded packet body.
//
// For definite-length packets it returns exactly the declared body bytes and
// then io.EOF. For partial packets the raw length octets are emitted ahead of
// each chunk. It never reads past the packet boundary.
func (p *RawPacket) Read(buf []byte) (int, error) {
	if p.done {
		return 0, io.EOF
	}
	if len(buf) == 0 {
		return 0, nil
	}

	if p.indeterminate {
		// Old-format length type 3: the body runs to the end of the stream.
		n, err := p.r.in.Read(buf)
		p.r.pos += int64(n)
		p.Consumed += int64(n)
		if err == io.EOF {
			p.done = true
		}
		return n, err
	}

	// Emit any pending raw length octets before reading chunk data.
	if len(p.pending) > 0 {
		n := copy(buf, p.pending)
		p.pending = p.pending[n:]
		p.Consumed += int64(n)
		return n, nil
	}

	// Definite body or current partial chunk exhausted.
	if p.remaining == 0 {
		if !p.inPartial {
			p.done = true
			return 0, io.EOF
		}
		first, err := readRawByte(p.r.in)
		if err != nil {
			return 0, p.truncated(err) // partial packets must end with a definite length
		}
		p.r.pos++
		if first >= 224 && first < 255 {
			// Another partial chunk, size 2^(first & 0x1f).
			p.remaining = int64(1) << (first & 0x1f)
			p.pending = []byte{first}
			n := copy(buf, p.pending)
			p.pending = p.pending[n:]
			p.Consumed += int64(n)
			return n, nil
		}
		// Definite final chunk using one, two or five length octets.
		length, extra, err := readDefiniteLength(p.r.in, first)
		if err != nil {
			return 0, p.truncated(err)
		}
		p.r.pos += int64(len(extra))
		p.inPartial = false
		p.remaining = length
		pending := make([]byte, 0, 1+len(extra))
		pending = append(pending, first)
		pending = append(pending, extra...)
		n := copy(buf, pending)
		p.pending = pending[n:]
		p.Consumed += int64(n)
		return n, nil
	}

	toRead := p.remaining
	if int64(len(buf)) < toRead {
		toRead = int64(len(buf))
	}
	n, err := p.r.in.Read(buf[:toRead])
	p.r.pos += int64(n)
	p.remaining -= int64(n)
	p.Consumed += int64(n)
	// A Reader may deliver the exact bytes that finish a chunk together with
	// io.EOF; that is still a clean chunk/body boundary.
	if err == io.EOF && p.remaining == 0 {
		err = nil
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n, p.truncated(err)
	}
	return n, nil
}

// Discard skips the remaining packet body, including raw partial length
// octets, leaving the reader positioned exactly at the next packet header.
func (p *RawPacket) Discard() error {
	if p.done {
		return nil
	}
	var buf [32 * 1024]byte
	for {
		n, err := p.Read(buf[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		_ = n
	}
	p.done = true
	return nil
}

// WriteTo copies the raw packet — header and body, including partial length
// octets — to w without buffering the body in memory.
func (p *RawPacket) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(p.Header)
	if err != nil {
		return int64(n), err
	}
	var buf [32 * 1024]byte
	var total int64
	for {
		m, err := p.Read(buf[:])
		if m > 0 {
			if _, werr := w.Write(buf[:m]); werr != nil {
				return int64(n) + total, werr
			}
			total += int64(m)
		}
		if err == io.EOF {
			return int64(n) + total, nil
		}
		if err != nil {
			return int64(n) + total, err
		}
	}
}

// readDefiniteLength decodes a definite length whose first octet is first
// (RFC 4880, section 4.2.2). It returns the decoded length and the extra raw
// octets consumed after first. The caller accounts for the stream position.
func readDefiniteLength(in byteReader, first byte) (int64, []byte, error) {
	switch {
	case first < 192:
		return int64(first), nil, nil
	case first < 224:
		second, err := readRawByte(in)
		if err != nil {
			return 0, nil, err
		}
		return int64(first-192)<<8 + int64(second) + 192, []byte{second}, nil
	default: // first == 255, five-octet length
		extra := make([]byte, 4)
		if _, err := readRawFull(in, extra); err != nil {
			return 0, nil, err
		}
		return int64(extra[0])<<24 |
			int64(extra[1])<<16 |
			int64(extra[2])<<8 |
			int64(extra[3]), extra, nil
	}
}

func (p *RawPacket) truncated(err error) error {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return &pgperrors.TruncatedPacketError{
		PacketNumber: p.r.number,
		Tag:          p.Tag,
		Offset:       p.r.pos,
		PacketOffset: p.r.pos - p.StartOffset,
		Err:          err,
	}
}

// RawReader reads packets while preserving every original header and length
// byte. It handles old and new format headers, definite lengths and partial
// body length encoding. Unknown tags are returned like any other; packets are
// never skipped.
type RawReader struct {
	in  byteReader
	pos int64

	// number is the 1-based index of the most recently started packet.
	number int

	current *RawPacket
}

// byteReader is the Reader interface RawReader needs. A plain io.Reader is
// wrapped without read-ahead so that header parsing never consumes body
// bytes.
type byteReader interface {
	io.Reader
	ReadByte() (byte, error)
}

type singleByteReader struct {
	r io.Reader
}

func (s singleByteReader) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s singleByteReader) ReadByte() (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(s.r, b[:])
	return b[0], err
}

// NewRawReader returns a RawReader over r.
func NewRawReader(r io.Reader) *RawReader {
	br, ok := r.(byteReader)
	if !ok {
		br = singleByteReader{r: r}
	}
	return &RawReader{in: br}
}

// Next returns the next raw packet. The returned packet must be fully read,
// copied or discarded before Next is called again; otherwise Next returns an
// error without consuming any byte.
//
// Old-format indeterminate-length packets (length type 3) cannot be followed
// by another packet on the same stream: their body extends to EOF, and any
// trailing bytes are, by definition, part of that body. Such a packet can
// therefore only be the last packet of the stream.
func (r *RawReader) Next() (*RawPacket, error) {
	if r.current != nil && !r.current.done {
		return nil, pgperrors.InvalidArgumentError("previous packet must be fully read, discarded or copied before calling Next")
	}

	start := r.pos
	tagByte, err := readRawByte(r.in)
	if err != nil {
		return nil, err
	}
	r.pos++
	r.number++

	p := &RawPacket{StartOffset: start, r: r}
	header := []byte{tagByte}

	if tagByte&0x80 == 0 {
		return nil, pgperrors.StructuralError("tag byte does not have MSB set")
	}

	if tagByte&0x40 == 0 {
		// Old format packet (RFC 4880, section 4.2.1).
		p.Tag = (tagByte & 0x3f) >> 2
		lengthType := tagByte & 0x03
		if lengthType == 3 {
			// Indeterminate length: body runs to the end of the stream.
			p.FixedLength = -1
			p.indeterminate = true
			p.Header = header
			r.current = p
			return p, nil
		}
		lengthBytes := int(1 << lengthType)
		lengthBuf := make([]byte, lengthBytes)
		if _, err := readRawFull(r.in, lengthBuf); err != nil {
			return nil, r.truncated(p, err)
		}
		r.pos += int64(lengthBytes)
		header = append(header, lengthBuf...)
		var length int64
		for _, b := range lengthBuf {
			length = length<<8 | int64(b)
		}
		p.FixedLength = length
		p.remaining = length
		p.Header = header
		r.current = p
		return p, nil
	}

	// New format packet (RFC 4880, section 4.2.2).
	p.Tag = tagByte & 0x3f
	first, err := readRawByte(r.in)
	if err != nil {
		return nil, r.truncated(p, err)
	}
	header = append(header, first)
	r.pos++
	switch {
	case first < 192:
		// One-octet definite length.
		p.FixedLength = int64(first)
		p.remaining = int64(first)
	case first < 224:
		// Two-octet definite length.
		length, extra, err := readDefiniteLength(r.in, first)
		if err != nil {
			return nil, r.truncated(p, err)
		}
		header = append(header, extra...)
		r.pos += int64(len(extra))
		p.FixedLength = length
		p.remaining = length
	case first < 255:
		// Partial body. The first length octet belongs to the header; later
		// chunk length octets come through the body stream.
		p.Partial = true
		p.inPartial = true
		p.FixedLength = -1
		p.remaining = int64(1) << (first & 0x1f)
	default:
		// Five-octet definite length.
		length, extra, err := readDefiniteLength(r.in, first)
		if err != nil {
			return nil, r.truncated(p, err)
		}
		header = append(header, extra...)
		r.pos += int64(len(extra))
		p.FixedLength = length
		p.remaining = length
	}
	p.Header = header
	r.current = p
	return p, nil
}

func (r *RawReader) truncated(p *RawPacket, err error) error {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return &pgperrors.TruncatedPacketError{
		PacketNumber: r.number,
		Tag:          p.Tag,
		Offset:       r.pos,
		PacketOffset: r.pos - p.StartOffset,
		Err:          err,
	}
}

func readRawByte(r byteReader) (byte, error) { return r.ReadByte() }

func readRawFull(r byteReader, buf []byte) (int, error) {
	for i := range buf {
		b, err := r.ReadByte()
		if err != nil {
			return i, err
		}
		buf[i] = b
	}
	return len(buf), nil
}
