// Copyright 2026 The ProtonMail Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package armor

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

// armorText builds an armored block with the given type, headers and body.
func armorText(typ string, headers []Header, body []byte, withCRC bool) string {
	var sb strings.Builder
	sb.WriteString("-----BEGIN " + typ + "-----\n")
	for _, h := range headers {
		sb.WriteString(h.Key + ": " + h.Value + "\n")
	}
	sb.WriteString("\n")
	encoded := base64.StdEncoding.EncodeToString(body)
	for len(encoded) > 64 {
		sb.WriteString(encoded[:64] + "\n")
		encoded = encoded[64:]
	}
	sb.WriteString(encoded + "\n")
	if withCRC {
		crc := &crc24Hasher{}
		crc.Reset()
		crc.Write(body)
		var sum [3]byte
		v := crc.Sum24()
		sum[0] = byte(v >> 16)
		sum[1] = byte(v >> 8)
		sum[2] = byte(v)
		sb.WriteString("=" + base64.StdEncoding.EncodeToString(sum[:]) + "\n")
	}
	sb.WriteString("-----END " + typ + "-----\n")
	return sb.String()
}

// oneByteReader returns at most one byte per Read call.
type oneByteReader struct {
	r io.Reader
}

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}

func TestScannerMultipleBlocks(t *testing.T) {
	body1 := []byte("first block body")
	body2 := []byte("second block body, no checksum")
	headers1 := []Header{
		{"Version", "1.0"},
		{"Comment", "first"},
		{"Comment", "second"},
	}
	input := "This is explanatory text.\nMore text: ----- not a marker.\n" +
		armorText("PGP MESSAGE", headers1, body1, true) +
		"text between blocks\n\n" +
		armorText("PGP SIGNATURE", nil, body2, false) +
		"trailing text\n"

	s := NewScanner(strings.NewReader(input), CRCVerify)

	b1, err := s.Next()
	if err != nil {
		t.Fatalf("Next block 1: %v", err)
	}
	if b1.Type != "PGP MESSAGE" {
		t.Errorf("block 1 type: got %q", b1.Type)
	}
	if len(b1.Header) != 3 || b1.Header[0] != headers1[0] || b1.Header[1] != headers1[1] || b1.Header[2] != headers1[2] {
		t.Errorf("block 1 headers: got %#v", b1.Header)
	}
	got1, err := io.ReadAll(b1.Body)
	if err != nil {
		t.Fatalf("block 1 body: %v", err)
	}
	if !bytes.Equal(got1, body1) {
		t.Errorf("block 1 body: got %q", got1)
	}
	off1 := s.Offset()
	if !strings.HasPrefix(input[off1:], "text between blocks\n") {
		t.Errorf("offset after block 1 = %d, remaining input starts with %q", off1, input[off1:])
	}

	b2, err := s.Next()
	if err != nil {
		t.Fatalf("Next block 2: %v", err)
	}
	if b2.Type != "PGP SIGNATURE" {
		t.Errorf("block 2 type: got %q", b2.Type)
	}
	if len(b2.Header) != 0 {
		t.Errorf("block 2 headers: got %#v", b2.Header)
	}
	got2, err := io.ReadAll(b2.Body)
	if err != nil {
		t.Fatalf("block 2 body: %v", err)
	}
	if !bytes.Equal(got2, body2) {
		t.Errorf("block 2 body: got %q", got2)
	}
	off2 := s.Offset()
	if !strings.HasPrefix(input[off2:], "trailing text\n") {
		t.Errorf("offset after block 2 = %d, remaining input starts with %q", off2, input[off2:])
	}

	if _, err := s.Next(); err != io.EOF {
		t.Errorf("final Next: got %v, want io.EOF", err)
	}
}

func TestScannerCRLF(t *testing.T) {
	body := []byte("crlf body")
	input := "intro\r\n" +
		strings.ReplaceAll(armorText("PGP MESSAGE", []Header{{"Version", "1"}}, body, true), "\n", "\r\n") +
		"outro\r\n"

	s := NewScanner(strings.NewReader(input), CRCVerify)
	b, err := s.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	got, err := io.ReadAll(b.Body)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body: got %q", got)
	}
	if off := s.Offset(); !strings.HasPrefix(input[off:], "outro\r\n") {
		t.Errorf("offset = %d, remaining input starts with %q", off, input[off:])
	}
}

func TestScannerOneByteReader(t *testing.T) {
	body1 := []byte("one")
	body2 := []byte("two")
	input := "intro\n" +
		armorText("PGP MESSAGE", nil, body1, true) +
		armorText("PGP PUBLIC KEY BLOCK", nil, body2, false)

	s := NewScanner(oneByteReader{r: strings.NewReader(input)}, CRCVerify)

	b1, err := s.Next()
	if err != nil {
		t.Fatalf("Next block 1: %v", err)
	}
	if _, err := io.ReadAll(b1.Body); err != nil {
		t.Fatalf("block 1 body: %v", err)
	}
	off1 := s.Offset()
	if !strings.HasPrefix(input[off1:], "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Errorf("offset after block 1 = %d, remaining input starts with %q", off1, input[off1:])
	}

	b2, err := s.Next()
	if err != nil {
		t.Fatalf("Next block 2: %v", err)
	}
	got2, err := io.ReadAll(b2.Body)
	if err != nil {
		t.Fatalf("block 2 body: %v", err)
	}
	if !bytes.Equal(got2, body2) {
		t.Errorf("block 2 body: got %q", got2)
	}
	if off2 := s.Offset(); off2 != int64(len(input)) {
		t.Errorf("offset after block 2 = %d, want %d", off2, len(input))
	}
}

func TestScannerSkipPartialBody(t *testing.T) {
	body1 := bytes.Repeat([]byte("0123456789"), 100)
	body2 := []byte("second")
	input := armorText("PGP MESSAGE", nil, body1, true) +
		armorText("PGP SIGNATURE", nil, body2, true)

	s := NewScanner(strings.NewReader(input), CRCVerify)
	b1, err := s.Next()
	if err != nil {
		t.Fatalf("Next block 1: %v", err)
	}

	// Consume only half of the body.
	half := make([]byte, len(body1)/2)
	if _, err := io.ReadFull(b1.Body, half); err != nil {
		t.Fatalf("partial read: %v", err)
	}

	// Scanning cannot continue until the block is finished.
	if _, err := s.Next(); err == nil {
		t.Fatal("Next before finishing previous block: expected error, got nil")
	}

	// Explicitly skip the rest of the block; the CRC is still verified.
	if err := b1.Skip(); err != nil {
		t.Fatalf("Skip: %v", err)
	}
	off1 := s.Offset()
	if !strings.HasPrefix(input[off1:], "-----BEGIN PGP SIGNATURE-----") {
		t.Errorf("offset after block 1 = %d, remaining input starts with %q", off1, input[off1:])
	}

	b2, err := s.Next()
	if err != nil {
		t.Fatalf("Next block 2: %v", err)
	}
	got2, err := io.ReadAll(b2.Body)
	if err != nil {
		t.Fatalf("block 2 body: %v", err)
	}
	if !bytes.Equal(got2, body2) {
		t.Errorf("block 2 body: got %q", got2)
	}
}

func TestScannerEndTypeMismatch(t *testing.T) {
	input := "-----BEGIN PGP MESSAGE-----\n\n" +
		"aGVsbG8=\n" +
		"-----END PGP SIGNATURE-----\n"
	s := NewScanner(strings.NewReader(input), CRCVerify)
	b, err := s.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, err := io.ReadAll(b.Body); !errors.Is(err, ArmorCorrupt) {
		t.Errorf("body read: got %v, want ArmorCorrupt", err)
	}
}

func TestScannerBadBase64(t *testing.T) {
	input := "-----BEGIN PGP MESSAGE-----\n\n" +
		"aGVs*bG8=\n" +
		"-----END PGP MESSAGE-----\n"
	s := NewScanner(strings.NewReader(input), CRCVerify)
	b, err := s.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, err := io.ReadAll(b.Body); !errors.Is(err, ErrArmorBadBase64) {
		t.Errorf("body read: got %v, want ErrArmorBadBase64", err)
	}
}

func TestScannerCRCMismatch(t *testing.T) {
	body := []byte("some body")
	good := armorText("PGP MESSAGE", nil, body, true)
	// Corrupt the checksum line.
	bad := strings.Replace(good, "=", "=AAAA", 1)
	// Rebuild properly: replace the whole CRC line with a wrong one.
	lines := strings.Split(good, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "=") {
			lines[i] = "=AAAA"
		}
	}
	bad = strings.Join(lines, "\n")

	s := NewScanner(strings.NewReader(bad), CRCVerify)
	b, err := s.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, err := io.ReadAll(b.Body); !errors.Is(err, ErrArmorCRCMismatch) {
		t.Errorf("body read: got %v, want ErrArmorCRCMismatch", err)
	}

	// With CRCIgnore, a wrong checksum is accepted.
	s = NewScanner(strings.NewReader(bad), CRCIgnore)
	b, err = s.Next()
	if err != nil {
		t.Fatalf("Next (ignore): %v", err)
	}
	got, err := io.ReadAll(b.Body)
	if err != nil {
		t.Fatalf("body read (ignore): %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body (ignore): got %q", got)
	}
}

func TestScannerMissingEnd(t *testing.T) {
	input := "-----BEGIN PGP MESSAGE-----\n\naGVsbG8=\n"
	s := NewScanner(strings.NewReader(input), CRCVerify)
	b, err := s.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, err := io.ReadAll(b.Body); !errors.Is(err, ErrArmorMissingEnd) {
		t.Errorf("body read: got %v, want ErrArmorMissingEnd", err)
	}
}

func TestScannerCRCRequire(t *testing.T) {
	body := []byte("required checksum")
	withCRC := armorText("PGP MESSAGE", nil, body, true)
	withoutCRC := armorText("PGP MESSAGE", nil, body, false)

	s := NewScanner(strings.NewReader(withoutCRC), CRCRequire)
	b, err := s.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, err := io.ReadAll(b.Body); !errors.Is(err, ErrArmorMissingCRC) {
		t.Errorf("body read: got %v, want ErrArmorMissingCRC", err)
	}

	s = NewScanner(strings.NewReader(withCRC), CRCRequire)
	b, err = s.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	got, err := io.ReadAll(b.Body)
	if err != nil {
		t.Fatalf("body read: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body: got %q", got)
	}
}

func TestScannerForbiddenCRC(t *testing.T) {
	// The Cleartext Signature Framework never carries an armor checksum.
	withCRC := armorText("PGP SIGNED MESSAGE", nil, []byte("x"), true)

	for _, policy := range []CRCPolicy{CRCIgnore, CRCVerify, CRCRequire} {
		s := NewScanner(strings.NewReader(withCRC), policy)
		b, err := s.Next()
		if policy == CRCRequire {
			if !errors.Is(err, ErrArmorForbiddenCRC) {
				t.Errorf("Next (require): got %v, want ErrArmorForbiddenCRC", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Next (policy %d): %v", policy, err)
		}
		if _, err := io.ReadAll(b.Body); !errors.Is(err, ErrArmorForbiddenCRC) {
			t.Errorf("body read (policy %d): got %v, want ErrArmorForbiddenCRC", policy, err)
		}
	}
}

func TestCRC24Vector(t *testing.T) {
	// Reference value from RFC 4880, section 6.1.
	crc := &crc24Hasher{}
	crc.Reset()
	crc.Write([]byte("123456789"))
	if got := crc.Sum24(); got != 0x21CF02 {
		t.Errorf("crc24 of %q: got %#06x, want 0x21cf02", "123456789", got)
	}
}
