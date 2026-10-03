package armor

import (
	"bytes"
	"encoding/base64"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

const crc24Mask = 0xffffff

// CRCPolicy controls strict armor CRC24 handling. A valid CRC24 only detects
// transport corruption; it does not authenticate the block as a signature does.
type CRCPolicy int

const (
	// CRCIgnore accepts a CRC24 line without checking it.
	CRCIgnore CRCPolicy = iota
	// CRCVerifyIfPresent verifies a CRC24 line when one is present.
	CRCVerifyIfPresent
	// CRCRequire requires and verifies a CRC24 line for types that allow one.
	CRCRequire
)

type scannerState int

const (
	statePreamble scannerState = iota
	stateBlock
	stateDone
	stateError
)

type endingKind int

const (
	endingNone endingKind = iota
	endingCRC
	endingEnd
)

var (
	errBlockOpen    = errors.StructuralError("previous armor block has not been fully read or skipped")
	errCRCMissing   = errors.StructuralError("armor CRC24 checksum is missing")
	errCRCForbidden = errors.StructuralError("armor CRC24 checksum is not allowed for this block type")
)

// Scanner reads strict OpenPGP armor blocks from a stream. It preserves the
// byte position immediately after each complete block and does not search for
// another block inside malformed data.
type Scanner struct {
	in     positionedLineReader
	policy CRCPolicy
	state  scannerState
	block  *Block
	err    error
}

// NewScanner creates a strict armor scanner. Explanatory text before a block
// and between complete blocks is skipped one line at a time.
func NewScanner(in io.Reader, policy CRCPolicy) (*Scanner, error) {
	if policy < CRCIgnore || policy > CRCRequire {
		return nil, errors.InvalidArgumentError("unknown armor CRC policy")
	}
	return &Scanner{in: positionedLineReader{in: in}, policy: policy}, nil
}

// Position returns the byte offset of the first unconsumed input byte.
func (s *Scanner) Position() int64 {
	return s.in.position()
}

// Next returns the next block. The returned block's Body must reach EOF or be
// skipped before Next is called again.
func (s *Scanner) Next() (*Block, error) {
	switch s.state {
	case stateError:
		return nil, s.err
	case stateDone:
		return nil, io.EOF
	case stateBlock:
		return nil, errBlockOpen
	}

	for {
		beginOffset := s.in.position()
		line, err := s.in.readLine()
		if err != nil {
			if err == io.EOF {
				s.state = stateDone
			} else {
				s.fail(err)
			}
			return nil, err
		}

		if bytes.HasPrefix(line, armorStart) {
			blockType, ok := parseDelimiter(line, armorStart, armorEndOfLine)
			if !ok {
				return nil, s.fail(ArmorCorrupt)
			}
			if blockType == "PGP SIGNED MESSAGE" {
				return nil, s.fail(errors.UnsupportedError("cleartext signed messages are not armor blocks"))
			}

			headers, err := s.readHeaders()
			if err != nil {
				return nil, s.fail(err)
			}

			body := &armorBody{
				scanner:   s,
				blockType: blockType,
				crc:       crc24Init,
			}
			source := &bodyLineSource{body: body}
			body.decoder = base64.NewDecoder(base64.StdEncoding, source)
			block := &Block{
				Type:    blockType,
				Header:  make(map[string]string),
				Headers: headers,
				Offset:  beginOffset,
				Body:    body,
				scanner: s,
			}
			for _, header := range headers {
				if _, exists := block.Header[header.Key]; !exists {
					block.Header[header.Key] = header.Value
				}
			}

			body.block = block
			s.block = block
			s.state = stateBlock
			return block, nil
		}
	}
}

// Skip reads and validates the remainder of the current block. It is safe to
// call when no block is open.
func (s *Scanner) Skip() error {
	if s.state != stateBlock {
		return s.err
	}
	_, err := io.Copy(io.Discard, s.block.Body)
	return err
}

// Skip reads and validates the remainder of a strict block.
func (b *Block) Skip() error {
	if b.scanner == nil {
		return errors.InvalidArgumentError("block was not created by a strict scanner")
	}
	return b.scanner.Skip()
}

func (s *Scanner) readHeaders() ([]Header, error) {
	var headers []Header
	for {
		line, err := s.in.readLine()
		if err != nil {
			return nil, ArmorCorrupt
		}
		if len(line) == 0 {
			return headers, nil
		}

		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !validHeaderKey(line[:colon]) {
			return nil, ArmorCorrupt
		}

		var value []byte
		if len(line) > colon+1 {
			if line[colon+1] != ' ' {
				return nil, ArmorCorrupt
			}
			value = line[colon+2:]
		}
		if !validHeaderValue(value) {
			return nil, ArmorCorrupt
		}

		headers = append(headers, Header{
			Key:   string(line[:colon]),
			Value: string(value),
		})
	}
}

func (s *Scanner) completeBlock(body *armorBody) error {
	if body.completed {
		return nil
	}
	body.completed = true

	var err error
	switch body.ending {
	case endingEnd:
		if s.policy == CRCRequire && crc24Allowed(body.blockType) {
			err = errCRCMissing
		}
	case endingCRC:
		if !crc24Allowed(body.blockType) {
			err = errCRCForbidden
		} else {
			if s.policy != CRCIgnore && body.expectedCRC != body.crc&crc24Mask {
				err = ArmorCorrupt
			}
			if err == nil {
				err = s.readEnd(body.blockType)
			}
		}
	default:
		err = ArmorCorrupt
	}

	if err != nil {
		return s.fail(err)
	}
	s.state = statePreamble
	s.block = nil
	return nil
}

func (s *Scanner) readEnd(blockType string) error {
	line, err := s.in.readLine()
	if err != nil {
		return ArmorCorrupt
	}
	endType, ok := parseDelimiter(line, armorEnd, armorEndOfLine)
	if !ok || endType != blockType {
		return ArmorCorrupt
	}
	return nil
}

func (s *Scanner) fail(err error) error {
	if s.state != stateError {
		s.err = err
		s.state = stateError
		s.block = nil
	}
	return err
}

type armorBody struct {
	scanner       *Scanner
	block         *Block
	decoder       io.Reader
	blockType     string
	ending        endingKind
	expectedCRC   uint32
	crc           uint32
	completed     bool
	terminalError error
}

func (b *armorBody) Read(p []byte) (int, error) {
	if b.terminalError != nil {
		return 0, b.terminalError
	}
	if b.completed {
		return 0, io.EOF
	}

	n, err := b.decoder.Read(p)
	b.crc = crc24(b.crc, p[:n])
	if err == nil {
		return n, nil
	}

	var readErr error
	if err != io.EOF {
		readErr = ArmorCorrupt
	} else {
		readErr = b.scanner.completeBlock(b)
	}
	if readErr != nil {
		b.terminalError = readErr
		return n, readErr
	}
	if n > 0 {
		return n, nil
	}
	return 0, io.EOF
}

type bodyLineSource struct {
	body    *armorBody
	pending []byte
}

func (s *bodyLineSource) Read(p []byte) (int, error) {
	b := s.body
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}

	line, err := b.scanner.in.readLine()
	if err != nil {
		return 0, ArmorCorrupt
	}

	if bytes.HasPrefix(line, armorEnd) {
		endType, ok := parseDelimiter(line, armorEnd, armorEndOfLine)
		if !ok || endType != b.blockType {
			return 0, ArmorCorrupt
		}
		b.ending = endingEnd
		return 0, io.EOF
	}

	if len(line) > 0 && line[0] == '=' {
		crc, ok := decodeCRC(line)
		if !ok {
			return 0, ArmorCorrupt
		}
		b.expectedCRC = crc
		b.ending = endingCRC
		return 0, io.EOF
	}

	if len(line) == 0 || len(line) > 76 || len(line)%4 != 0 || !validBase64Line(line) {
		return 0, ArmorCorrupt
	}

	s.pending = append(line, '\n')
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

type positionedLineReader struct {
	in       io.Reader
	buf      []byte
	consumed int64
}

func (r *positionedLineReader) position() int64 {
	return r.consumed - int64(len(r.buf))
}

func (r *positionedLineReader) readLine() ([]byte, error) {
	for {
		if index := bytes.IndexByte(r.buf, '\n'); index >= 0 {
			line := r.buf[:index]
			r.buf = r.buf[index+1:]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			return line, nil
		}

		var tmp [4096]byte
		n, err := r.in.Read(tmp[:])
		if n > 0 {
			r.buf = append(r.buf, tmp[:n]...)
			r.consumed += int64(n)
		}
		if err != nil {
			if err == io.EOF && len(r.buf) > 0 {
				line := r.buf
				r.buf = nil
				return line, nil
			}
			return nil, err
		}
	}
}

func parseDelimiter(line, prefix, suffix []byte) (string, bool) {
	if !bytes.HasPrefix(line, prefix) || !bytes.HasSuffix(line, suffix) {
		return "", false
	}
	blockType := line[len(prefix) : len(line)-len(suffix)]
	if !validArmorType(blockType) {
		return "", false
	}
	return string(blockType), true
}

func validArmorType(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for i, b := range value {
		if b == ' ' {
			if i == 0 || i == len(value)-1 || value[i-1] == ' ' {
				return false
			}
			continue
		}
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func validHeaderKey(value []byte) bool {
	for _, b := range value {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
			b >= '0' && b <= '9' || b == '-' || b == '_' {
			continue
		}
		return false
	}
	return true
}

func validHeaderValue(value []byte) bool {
	for _, b := range value {
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func validBase64Line(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	decodedLen := base64.StdEncoding.DecodedLen(len(line))
	decoded := make([]byte, decodedLen)
	_, err := base64.StdEncoding.Decode(decoded, line)
	return err == nil
}

func decodeCRC(line []byte) (uint32, bool) {
	if len(line) != 5 || line[0] != '=' {
		return 0, false
	}
	var decoded [3]byte
	n, err := base64.StdEncoding.Decode(decoded[:], line[1:])
	if err != nil || n != 3 {
		return 0, false
	}
	return uint32(decoded[0])<<16 | uint32(decoded[1])<<8 | uint32(decoded[2]), true
}

func crc24Allowed(blockType string) bool {
	switch blockType {
	case "PGP MESSAGE", "PGP PUBLIC KEY BLOCK", "PGP PRIVATE KEY BLOCK", "PGP SIGNATURE":
		return true
	default:
		return false
	}
}
