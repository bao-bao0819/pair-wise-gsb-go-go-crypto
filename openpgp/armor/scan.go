// Copyright 2026 The ProtonMail Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package armor

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// This file implements a strict, resumable scanner for OpenPGP ASCII armor.
// Unlike Decode, which is lenient and consumes an arbitrary amount of input
// past the end of a block, a Scanner parses each block according to an
// explicit grammar, reports the exact input offset just past the end of
// every block, and never silently skips malformed data in order to find the
// next block.
//
// The grammar accepted by the scanner is:
//
//	input   = *( text-line ) *( block *( text-line ) )
//	block   = begin-line *( header-line ) empty-line
//	          *( base64-line ) [ crc-line ] end-line
//
// A text-line is any line not starting with "-----". Empty lines are not
// allowed inside a block body. Lines may be terminated by LF or CRLF; any
// other surrounding whitespace is rejected. The type in the END line must
// match the type in the BEGIN line exactly.

// CRCPolicy determines how a Scanner treats the optional CRC24 armor
// checksum (RFC 4880, section 6; deprecated by RFC 9580).
//
// Note that the CRC24 is only a transport checksum: a matching CRC does not
// imply any authenticity or integrity guarantee and must never be treated
// as a successful signature verification.
type CRCPolicy int

const (
	// CRCIgnore makes the scanner accept and discard a CRC24 checksum line
	// without verifying it.
	CRCIgnore CRCPolicy = iota
	// CRCVerify makes the scanner verify the CRC24 checksum if one is
	// present, and accept blocks without one.
	CRCVerify
	// CRCRequire makes the scanner require a CRC24 checksum line and
	// verify it.
	CRCRequire
)

// Errors returned by the strict scanner. Distinct failures are reported as
// distinct sentinel errors so callers can react with errors.Is.
var (
	// ErrArmorBadBase64 is returned when the body of a block contains
	// data that is not valid base64.
	ErrArmorBadBase64 error = errors.StructuralError("armor: invalid base64 data in block body")
	// ErrArmorCRCMismatch is returned when a present CRC24 checksum does
	// not match the decoded body and the policy requires verification.
	ErrArmorCRCMismatch error = errors.StructuralError("armor: CRC24 checksum mismatch")
	// ErrArmorMissingEnd is returned when the input ends, or the data
	// cannot be delimited, before the END line of a block.
	ErrArmorMissingEnd error = errors.StructuralError("armor: missing END line")
	// ErrArmorMissingCRC is returned when the policy is CRCRequire but a
	// block carries no CRC24 checksum.
	ErrArmorMissingCRC error = errors.StructuralError("armor: missing CRC24 checksum")
	// ErrArmorForbiddenCRC is returned when a CRC24 checksum appears on a
	// block type for which the current OpenPGP specification forbids it.
	ErrArmorForbiddenCRC error = errors.StructuralError("armor: CRC24 checksum not allowed for this armor type")
)

// crcForbiddenType reports whether the given armor type must not carry a
// CRC24 checksum according to the current OpenPGP specification (RFC 9580).
// The Cleartext Signature Framework ("PGP SIGNED MESSAGE", RFC 9580,
// section 7) is not base64 armored data and never carries an armor
// checksum. RFC 9580 additionally deprecates the CRC24 for all other types,
// but still permits receiving it there.
func crcForbiddenType(typ string) bool {
	return typ == "PGP SIGNED MESSAGE"
}

// A Header is a single armor header line. Unlike the map in Block, a slice
// of Header preserves the original order and any duplicate keys.
type Header struct {
	Key   string
	Value string
}

// A StrictBlock is a single armored block returned by Scanner.Next.
type StrictBlock struct {
	Type   string   // The type, taken from the BEGIN line (i.e. "PGP SIGNATURE").
	Header []Header // Optional headers, in order, duplicates preserved.
	Body   io.Reader

	scanner  *Scanner
	crc      *crc24Hasher
	finished bool
}

// Skip discards the remainder of the block's body. It allows a caller that
// has only consumed part of Body to finish the block so that the scanner can
// continue with the next one. Skip still verifies the CRC24 checksum if the
// scanner's policy requires it, and returns any error encountered while
// consuming the rest of the block.
func (b *StrictBlock) Skip() error {
	if b.finished {
		return nil
	}
	_, err := io.Copy(io.Discard, b.Body)
	return err
}

// countingReader counts the number of bytes read from the underlying reader.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// A Scanner reads a sequence of armored blocks from an input stream,
// skipping any explanatory text between blocks.
type Scanner struct {
	cr      *countingReader
	in      *bufio.Reader
	policy  CRCPolicy
	current *StrictBlock
	offset  int64
	eof     bool
}

// NewScanner returns a Scanner that reads armored blocks from in according
// to the given CRC24 policy. The input may contain arbitrary explanatory
// text before, between, and after blocks.
func NewScanner(in io.Reader, policy CRCPolicy) *Scanner {
	cr := &countingReader{r: in}
	return &Scanner{
		cr:     cr,
		in:     bufio.NewReader(cr),
		policy: policy,
	}
}

// Offset returns the number of bytes consumed from the underlying reader up
// to and including the END line of the most recently completed block. It is
// only meaningful after that block's Body has been read to EOF or Skip has
// been called on it. The remaining input, starting at Offset, is untouched:
// in particular it still contains the beginning of the next block, if any.
func (s *Scanner) Offset() int64 {
	return s.offset
}

// Next advances the scanner to the next armored block and returns it, or
// io.EOF if no further block is present. The previous block must have been
// fully consumed first: either read its Body to EOF or call its Skip
// method, otherwise Next returns an error.
func (s *Scanner) Next() (*StrictBlock, error) {
	if s.eof {
		return nil, io.EOF
	}
	if s.current != nil && !s.current.finished {
		return nil, errors.StructuralError("armor: previous block not fully consumed: read Body to EOF or call Skip")
	}
	s.current = nil

	// Skip explanatory text until a BEGIN line is found.
	var typ string
	for {
		line, err := s.readLine()
		if err != nil {
			if err == io.EOF {
				s.eof = true
			}
			return nil, err
		}
		if !strings.HasPrefix(line, "-----BEGIN") {
			// Explanatory text, including stray non-BEGIN marker lines.
			continue
		}
		typ, err = parseBeginLine(line)
		if err != nil {
			return nil, err
		}
		break
	}

	if s.policy == CRCRequire && crcForbiddenType(typ) {
		return nil, fmt.Errorf("armor: cannot require a CRC24 checksum for type %q: %w", typ, ErrArmorForbiddenCRC)
	}

	// Read headers until the empty separator line.
	var headers []Header
	for {
		line, err := s.readLine()
		if err != nil {
			if err == io.EOF {
				return nil, ErrArmorMissingEnd
			}
			return nil, err
		}
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "-----") {
			return nil, fmt.Errorf("armor: unexpected marker line %q in headers of %q block: %w", line, typ, ArmorCorrupt)
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 || i+1 >= len(line) || line[i+1] != ' ' {
			return nil, fmt.Errorf("armor: malformed header line %q: %w", line, ArmorCorrupt)
		}
		key := line[:i]
		for j := 0; j < len(key); j++ {
			c := key[j]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return nil, fmt.Errorf("armor: malformed header key %q: %w", key, ArmorCorrupt)
			}
		}
		headers = append(headers, Header{Key: key, Value: line[i+2:]})
	}

	b := &StrictBlock{
		Type:    typ,
		Header:  headers,
		scanner: s,
		crc:     &crc24Hasher{},
	}
	b.crc.Reset()
	lines := &bodyLineReader{block: b}
	b.Body = &checksumReader{
		r:   base64.NewDecoder(base64.StdEncoding, lines),
		crc: b.crc,
	}
	s.current = b
	return b, nil
}

// readLine reads a single line, stripping a trailing LF or CRLF. A final
// line without a trailing newline is accepted.
func (s *Scanner) readLine() (string, error) {
	line, err := s.in.ReadString('\n')
	if err != nil {
		if err == io.EOF && len(line) > 0 {
			return strings.TrimSuffix(line, "\r"), nil
		}
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

// parseBeginLine parses a "-----BEGIN Type-----" line and returns the type.
func parseBeginLine(line string) (string, error) {
	rest := line[len("-----BEGIN"):]
	if !strings.HasPrefix(rest, " ") || !strings.HasSuffix(rest, "-----") {
		return "", fmt.Errorf("armor: malformed BEGIN line %q: %w", line, ArmorCorrupt)
	}
	typ := rest[1 : len(rest)-len("-----")]
	if typ == "" || strings.TrimSpace(typ) != typ || strings.Contains(typ, "-----") {
		return "", fmt.Errorf("armor: malformed BEGIN line %q: %w", line, ArmorCorrupt)
	}
	return typ, nil
}

// finish marks the block as completed and records the input offset just
// past its END line.
func (b *StrictBlock) finish() {
	b.finished = true
	s := b.scanner
	s.offset = s.cr.n - int64(s.in.Buffered())
}

// bodyLineReader yields the raw base64 lines of a block body to the base64
// decoder and handles the CRC24 and END lines that terminate the body.
type bodyLineReader struct {
	block *StrictBlock
	buf   []byte
	eof   bool
}

func (r *bodyLineReader) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}
	if len(r.buf) == 0 {
		if err := r.nextLine(); err != nil {
			return 0, err
		}
		if r.eof {
			return 0, io.EOF
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *bodyLineReader) nextLine() error {
	s := r.block.scanner
	wantEnd := "-----END " + r.block.Type + "-----"

	line, err := s.readLine()
	if err != nil {
		if err == io.EOF {
			return ErrArmorMissingEnd
		}
		return err
	}

	switch {
	case strings.HasPrefix(line, "-----END"):
		if line != wantEnd {
			return fmt.Errorf("armor: END line %q does not match BEGIN type %q: %w", line, r.block.Type, ArmorCorrupt)
		}
		if s.policy == CRCRequire {
			return ErrArmorMissingCRC
		}
		r.eof = true
		r.block.finish()
		return nil
	case isCRCLine(line):
		if crcForbiddenType(r.block.Type) {
			return ErrArmorForbiddenCRC
		}
		if s.policy != CRCIgnore {
			expected, decErr := base64.StdEncoding.DecodeString(line[1:])
			if decErr != nil || len(expected) != 3 {
				return fmt.Errorf("armor: malformed CRC24 line %q: %w", line, ArmorCorrupt)
			}
			got := r.block.crc.Sum24()
			if uint32(expected[0])<<16|uint32(expected[1])<<8|uint32(expected[2]) != got {
				return ErrArmorCRCMismatch
			}
		}
		// A CRC24 line must be immediately followed by the END line.
		line, err = s.readLine()
		if err != nil {
			if err == io.EOF {
				return ErrArmorMissingEnd
			}
			return err
		}
		if line != wantEnd {
			return fmt.Errorf("armor: END line %q does not match BEGIN type %q: %w", line, r.block.Type, ArmorCorrupt)
		}
		r.eof = true
		r.block.finish()
		return nil
	case line == "":
		return fmt.Errorf("armor: unexpected empty line in body of %q block: %w", r.block.Type, ArmorCorrupt)
	default:
		r.buf = []byte(line)
		return nil
	}
}

// isCRCLine reports whether line is a CRC24 checksum line: an '=' followed
// by the four base64 characters encoding 24 bits.
func isCRCLine(line string) bool {
	return len(line) == 5 && line[0] == '='
}

// checksumReader updates the CRC24 with the decoded body bytes as they are
// read and maps base64 decoding failures to ErrArmorBadBase64.
type checksumReader struct {
	r   io.Reader
	crc *crc24Hasher
}

func (c *checksumReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.crc.Write(p[:n])
	}
	if err != nil {
		if corrupt, ok := err.(base64.CorruptInputError); ok {
			err = fmt.Errorf("%w (at input byte %d)", ErrArmorBadBase64, int64(corrupt))
		}
	}
	return n, err
}

// crc24Hasher is a streaming wrapper around the crc24 function from
// encode.go, implementing the OpenPGP CRC24 checksum (RFC 4880, section
// 6.1).
type crc24Hasher struct {
	sum uint32
}

func (c *crc24Hasher) Reset() {
	c.sum = crc24Init
}

func (c *crc24Hasher) Write(p []byte) (int, error) {
	c.sum = crc24(c.sum, p)
	return len(p), nil
}

// Sum24 returns the 24-bit checksum of the data written so far.
func (c *crc24Hasher) Sum24() uint32 {
	return c.sum
}
