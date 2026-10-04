// Copyright 2026 The ProtonMail Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// RawPacketError describes a failure to read a packet at the raw byte
// level, for example a truncated header or body. It carries the packet
// number and the absolute offset of the packet in the original stream so
// that callers (e.g. archival tools) can locate the offending packet. A
// packet that failed with a RawPacketError was never fully read: no
// seemingly complete packet is fabricated from truncated data.
type RawPacketError struct {
	// Seq is the zero-based packet number in the stream.
	Seq uint64
	// Offset is the absolute byte offset of the packet header in the
	// original stream.
	Offset int64
	// Err is the underlying error, e.g. io.ErrUnexpectedEOF.
	Err error
}

func (e *RawPacketError) Error() string {
	return fmt.Sprintf("openpgp: raw packet %d at offset %d: %v", e.Seq, e.Offset, e.Err)
}

func (e *RawPacketError) Unwrap() error {
	return e.Err
}

// RawSegment describes one segment of a partial body (RFC 4880, section
// 4.2.2.4). The raw length encoding of every segment is preserved so that
// a partial body can be reproduced byte-for-byte.
type RawSegment struct {
	// LengthBytes is the raw wire encoding of this segment's length. For
	// the first segment it aliases the last byte of RawPacket.Header,
	// since the first partial length octet is part of the packet header.
	LengthBytes []byte
	// Length is the number of content bytes in this segment.
	Length int64
	// Final is true for the last segment, which uses a definite
	// (non-partial) length encoding.
	Final bool
}

// RawPacket is an OpenPGP packet read at the raw byte level. Unlike
// OpaquePacket, it preserves the exact header and length encodings of the
// packet, so a stream can be split into packets and reassembled
// byte-for-byte. The packet contents are not parsed; packets with unknown
// tags are returned like any other packet and never skipped.
type RawPacket struct {
	// Seq is the zero-based packet number in the stream.
	Seq uint64
	// Tag is the packet tag. Packets of any tag, known or unknown, are
	// returned.
	Tag uint8
	// Offset is the absolute byte offset of the first header byte in the
	// original stream.
	Offset int64
	// Header is the raw wire encoding of the packet header: the tag byte
	// followed by the (first) length encoding. For partial bodies this
	// includes the first partial length octet; the length octets of the
	// remaining segments appear inside the body and are exposed through
	// NextSegment and Segments.
	Header []byte
	// Length is the definite content length in bytes, or -1 if the body
	// is partial or indeterminate.
	Length int64
	// Partial is true if the body uses partial body lengths (new format
	// only).
	Partial bool
	// Indeterminate is true for old-format packets with length type 3,
	// whose body extends to the end of the stream. Because no length is
	// encoded, no packet boundary can be determined after such a packet:
	// everything up to EOF is its body, so it can only be the last
	// packet of a stream.
	Indeterminate bool
	// Segments collects the segments of a partial body as the body is
	// consumed. It is complete only after the body has been read to EOF.
	// It is nil for non-partial bodies.
	Segments []RawSegment

	body *rawBodyReader
}

// Contents returns a bounded stream of the packet body: it yields exactly
// the content bytes of this packet and then io.EOF. For partial bodies
// the segment length octets are stripped; use NextSegment (or Segments
// after the body has been consumed) to recover them. Contents reads from
// the underlying stream on demand and never reads beyond the end of the
// packet.
func (p *RawPacket) Contents() io.Reader {
	return p.body
}

// NextSegment returns the segment that upcoming reads from Contents
// belong to. It is only valid for partial bodies. It does not consume
// content: after obtaining a segment, the caller reads exactly
// segment.Length bytes from Contents and may then call NextSegment again
// for the following segment. It returns io.EOF once the final segment has
// been fully consumed.
func (p *RawPacket) NextSegment() (*RawSegment, error) {
	if !p.Partial {
		return nil, errors.StructuralError("packet does not have a partial body")
	}
	b := p.body
	if b.done {
		return nil, io.EOF
	}
	if b.rr.err != nil {
		return nil, b.rr.err
	}
	if b.remaining == 0 {
		if b.finalSegment {
			b.finish()
			return nil, io.EOF
		}
		if err := b.advance(); err != nil {
			return nil, err
		}
	}
	seg := p.Segments[len(p.Segments)-1]
	return &seg, nil
}

// CopyTo writes the packet to w exactly as it appeared in the input
// stream: the raw header followed by the raw body, including the length
// octets of every partial segment. It consumes the remainder of the
// body. The returned count is the total number of bytes written. If the
// body is truncated, an error (a *RawPacketError) is returned and the
// output must be discarded: no seemingly complete packet is produced
// from truncated input.
func (p *RawPacket) CopyTo(w io.Writer) (int64, error) {
	var total int64
	n, err := w.Write(p.Header)
	total += int64(n)
	if err != nil {
		return total, err
	}
	if !p.Partial {
		m, err := io.Copy(w, p.Contents())
		return total + m, err
	}
	first := true
	for {
		seg, err := p.NextSegment()
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
		if !first {
			m, err := w.Write(seg.LengthBytes)
			total += int64(m)
			if err != nil {
				return total, err
			}
		}
		first = false
		m, err := io.CopyN(w, p.Contents(), seg.Length)
		total += m
		if err != nil {
			return total, err
		}
	}
}

// Skip discards the remainder of the packet body and returns the number
// of content bytes skipped. For an indeterminate old-format packet this
// drains the rest of the stream.
func (p *RawPacket) Skip() (int64, error) {
	return io.Copy(io.Discard, p.Contents())
}

// countingReader counts the bytes read from an underlying reader so that
// absolute stream offsets can be reported.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// rawBodyReader is the bounded content stream of a RawPacket.
type rawBodyReader struct {
	pkt *RawPacket
	rr  *RawReader

	remaining    int64 // content bytes left in the current segment (or body)
	finalSegment bool  // current segment is final, or body has a definite length
	done         bool
}

func (b *rawBodyReader) finish() {
	b.done = true
	b.rr.open = false
}

// advance reads the length octets of the next partial segment from the
// underlying stream and records the segment.
func (b *rawBodyReader) advance() error {
	if b.rr.err != nil {
		return b.rr.err
	}
	length, isPartial, raw, err := readRawLength(b.rr.cr)
	if err != nil {
		return b.fail(err)
	}
	b.pkt.Segments = append(b.pkt.Segments, RawSegment{
		LengthBytes: raw,
		Length:      length,
		Final:       !isPartial,
	})
	b.remaining = length
	b.finalSegment = !isPartial
	if b.finalSegment && length == 0 {
		b.finish()
	}
	return nil
}

// fail converts a body read error into a *RawPacketError and makes it
// sticky on the RawReader: after a truncated body the stream position is
// unknown, so no further packets may be read.
func (b *rawBodyReader) fail(err error) error {
	perr := &RawPacketError{Seq: b.pkt.Seq, Offset: b.pkt.Offset, Err: err}
	b.rr.err = perr
	return perr
}

func (b *rawBodyReader) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	if b.rr.err != nil {
		return 0, b.rr.err
	}
	if b.pkt.Indeterminate {
		// Old-format indeterminate body: everything up to EOF. A clean
		// EOF terminates the packet; there is no truncation to detect.
		n, err := b.rr.cr.Read(p)
		if err == io.EOF {
			b.finish()
			if n > 0 {
				return n, nil
			}
			return 0, io.EOF
		}
		if err != nil {
			return n, b.fail(err)
		}
		return n, nil
	}
	for b.remaining == 0 {
		if b.finalSegment {
			b.finish()
			return 0, io.EOF
		}
		if err := b.advance(); err != nil {
			return 0, err
		}
		if b.done {
			return 0, io.EOF
		}
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.rr.cr.Read(p)
	b.remaining -= int64(n)
	if err == io.EOF {
		if b.remaining > 0 {
			return n, b.fail(io.ErrUnexpectedEOF)
		}
		err = nil
	}
	if err != nil {
		return n, b.fail(err)
	}
	if b.remaining == 0 && b.finalSegment {
		b.finish()
	}
	return n, nil
}

// RawReader reads OpenPGP packets from a stream at the raw byte level,
// preserving the exact wire encoding of every packet header and length
// fragment. It is meant for tools that split a message into packets and
// reassemble it later (or forward packets) without altering any bytes,
// e.g. archival software. Unlike Reader, it does not parse packet
// contents and does not skip unknown or unsupported packet tags.
//
// The caller drives consumption explicitly: after Next returns a packet,
// its body must be fully read from Contents, copied with CopyTo, or
// discarded with Skip before Next is called again. Next refuses to
// advance past an unfinished packet and returns an error instead of
// silently discarding data.
//
// Old-format packets with an indeterminate length (length type 3) extend
// to the end of the stream: no packet boundary can be determined after
// them, so they can only be the last packet of a stream.
type RawReader struct {
	cr   *countingReader
	seq  uint64
	open bool // a packet body is currently unconsumed

	openSeq    uint64
	openOffset int64

	err error // sticky error after a truncated packet
}

// NewRawReader returns a RawReader reading packets from r.
func NewRawReader(r io.Reader) *RawReader {
	return &RawReader{cr: &countingReader{r: r}}
}

// Next reads the next packet header and returns the packet. Only the
// header is consumed from the underlying stream; the body is read on
// demand through the returned packet. Next returns io.EOF at a clean
// packet boundary at the end of the stream. If the previous packet's
// body has not been fully consumed (read to EOF, CopyTo, or Skip), Next
// returns an error. If the stream is truncated or malformed, the error
// is a *RawPacketError carrying the packet number and offset.
func (r *RawReader) Next() (*RawPacket, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.open {
		return nil, &RawPacketError{
			Seq:    r.openSeq,
			Offset: r.openOffset,
			Err: errors.StructuralError(
				"previous packet body not fully consumed: read Contents to EOF, or call CopyTo or Skip, before Next"),
		}
	}
	offset := r.cr.n
	tag, header, length, partial, indeterminate, err := readRawHeader(r.cr)
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		r.err = &RawPacketError{Seq: r.seq, Offset: offset, Err: err}
		return nil, r.err
	}
	pkt := &RawPacket{
		Seq:           r.seq,
		Tag:           tag,
		Offset:        offset,
		Header:        header,
		Partial:       partial,
		Indeterminate: indeterminate,
	}
	body := &rawBodyReader{pkt: pkt, rr: r}
	switch {
	case partial:
		pkt.Length = -1
		// The first partial length octet is part of the header.
		pkt.Segments = []RawSegment{{
			LengthBytes: header[len(header)-1:],
			Length:      length,
			Final:       false,
		}}
		body.remaining = length
	case indeterminate:
		pkt.Length = -1
	default:
		pkt.Length = length
		body.remaining = length
		body.finalSegment = true
	}
	pkt.body = body
	r.seq++
	if indeterminate || partial || length > 0 {
		r.open = true
		r.openSeq = pkt.Seq
		r.openOffset = pkt.Offset
	} else {
		// Empty definite-length body: nothing to consume.
		body.finish()
	}
	return pkt, nil
}

// readRawLength reads an OpenPGP length from r, additionally returning
// the raw bytes of the encoding. See RFC 4880, section 4.2.2.
func readRawLength(r io.Reader) (length int64, isPartial bool, raw []byte, err error) {
	var buf [5]byte
	_, err = readFull(r, buf[:1])
	if err != nil {
		return
	}
	switch {
	case buf[0] < 192:
		length = int64(buf[0])
		raw = append([]byte(nil), buf[:1]...)
	case buf[0] < 224:
		_, err = readFull(r, buf[1:2])
		if err != nil {
			return
		}
		length = int64(buf[0]-192)<<8 + int64(buf[1]) + 192
		raw = append([]byte(nil), buf[:2]...)
	case buf[0] < 255:
		length = int64(1) << (buf[0] & 0x1f)
		isPartial = true
		raw = append([]byte(nil), buf[:1]...)
	default:
		_, err = readFull(r, buf[1:5])
		if err != nil {
			return
		}
		length = int64(buf[1])<<24 |
			int64(buf[2])<<16 |
			int64(buf[3])<<8 |
			int64(buf[4])
		raw = append([]byte(nil), buf[:5]...)
	}
	return
}

// readRawHeader parses a packet header and returns its raw bytes along
// with the decoded fields. A clean io.EOF (before the first header byte)
// signals the end of the stream; a truncated header yields
// io.ErrUnexpectedEOF. See RFC 4880, section 4.2.
func readRawHeader(r io.Reader) (tag uint8, header []byte, length int64, partial, indeterminate bool, err error) {
	var buf [4]byte
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return
	}
	if buf[0]&0x80 == 0 {
		err = errors.StructuralError("tag byte does not have MSB set")
		return
	}
	header = append(header, buf[0])
	if buf[0]&0x40 == 0 {
		// Old format packet
		tag = (buf[0] & 0x3f) >> 2
		lengthType := buf[0] & 3
		if lengthType == 3 {
			indeterminate = true
			length = -1
			return
		}
		lengthBytes := 1 << lengthType
		_, err = readFull(r, buf[:lengthBytes])
		if err != nil {
			return
		}
		header = append(header, buf[:lengthBytes]...)
		for i := 0; i < lengthBytes; i++ {
			length <<= 8
			length |= int64(buf[i])
		}
		return
	}

	// New format packet
	tag = buf[0] & 0x3f
	var raw []byte
	var isPartial bool
	length, isPartial, raw, err = readRawLength(r)
	if err != nil {
		return
	}
	header = append(header, raw...)
	partial = isPartial
	return
}
