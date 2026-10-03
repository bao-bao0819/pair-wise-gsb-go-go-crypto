package armor

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

type strictBlockSpec struct {
	blockType string
	headers   []Header
	payload   []byte
	crc       bool
	badCRC    bool
	badBase64 bool
	noEnd     bool
	wrongEnd  string
}

type oneByteReader struct {
	in []byte
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.in) == 0 {
		return 0, io.EOF
	}
	p[0] = r.in[0]
	r.in = r.in[1:]
	return 1, nil
}

func TestStrictScannerMultipleBlocks(t *testing.T) {
	firstPayload := bytes.Repeat([]byte("first armored payload "), 20)
	secondPayload := []byte("second")
	input := []byte("explanatory text\r\n")
	firstBlock := encodeStrictBlock(strictBlockSpec{
		blockType: "PGP SIGNATURE",
		headers: []Header{
			{Key: "Version", Value: "1.0"},
			{Key: "Comment", Value: "first"},
			{Key: "Version", Value: "2.0"},
			{Key: "Empty", Value: ""},
		},
		payload: firstPayload,
		crc:     true,
	}, "\r\n")
	input = append(input, firstBlock...)
	input = append(input, []byte("between blocks\r\n")...)
	input = append(input, encodeStrictBlock(strictBlockSpec{
		blockType: "X-CUSTOM",
		payload:   secondPayload,
	}, "\r\n")...)

	scanner, err := NewScanner(&oneByteReader{in: input}, CRCVerifyIfPresent)
	if err != nil {
		t.Fatal(err)
	}

	first, err := scanner.Next()
	if err != nil {
		t.Fatal(err)
	}
	if first.Type != "PGP SIGNATURE" {
		t.Fatalf("type = %q", first.Type)
	}
	if first.Offset != int64(strings.Index(string(input), "-----BEGIN PGP SIGNATURE-----")) {
		t.Fatalf("first offset = %d, want %d", first.Offset, strings.Index(string(input), "-----BEGIN PGP SIGNATURE-----"))
	}
	if got := first.Headers; len(got) != 4 ||
		got[0] != (Header{Key: "Version", Value: "1.0"}) ||
		got[1] != (Header{Key: "Comment", Value: "first"}) ||
		got[2] != (Header{Key: "Version", Value: "2.0"}) ||
		got[3] != (Header{Key: "Empty", Value: ""}) {
		t.Fatalf("headers = %#v", got)
	}
	if first.Header["Version"] != "1.0" {
		t.Fatalf("duplicate Header map value = %q", first.Header["Version"])
	}

	gotPayload, err := io.ReadAll(first.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, firstPayload) {
		t.Fatalf("first payload length = %d, want %d", len(gotPayload), len(firstPayload))
	}

	wantPosition := first.Offset + int64(len(firstBlock))
	if scanner.Position() != wantPosition {
		t.Fatalf("position after first = %d, want %d", scanner.Position(), wantPosition)
	}

	second, err := scanner.Next()
	if err != nil {
		t.Fatal(err)
	}
	gotPayload, err = io.ReadAll(second.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, secondPayload) {
		t.Fatalf("second payload = %q", gotPayload)
	}
	if scanner.Position() != int64(len(input)) {
		t.Fatalf("final position = %d, want %d", scanner.Position(), len(input))
	}
	if _, err = scanner.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next after end = %v, want io.EOF", err)
	}
}

func TestStrictScannerPartialReadThenSkip(t *testing.T) {
	firstPayload := []byte("0123456789abcdef")
	secondPayload := []byte("tail block")
	input := encodeStrictBlock(strictBlockSpec{
		blockType: "PGP MESSAGE",
		payload:   firstPayload,
		crc:       true,
	}, "\n")
	input = append(input, encodeStrictBlock(strictBlockSpec{
		blockType: "PGP PUBLIC KEY BLOCK",
		payload:   secondPayload,
	}, "\n")...)

	scanner, err := NewScanner(bytes.NewReader(input), CRCVerifyIfPresent)
	if err != nil {
		t.Fatal(err)
	}
	first, err := scanner.Next()
	if err != nil {
		t.Fatal(err)
	}

	partial := make([]byte, 1)
	if _, err = first.Body.Read(partial); err != nil {
		t.Fatal(err)
	}
	if partial[0] != firstPayload[0] {
		t.Fatalf("partial byte = %q", partial[0])
	}
	if _, err = scanner.Next(); err == nil {
		t.Fatal("Next succeeded before the current block was consumed")
	}
	if err = first.Skip(); err != nil {
		t.Fatal(err)
	}

	secondStart := int64(strings.Index(string(input), "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
	if scanner.Position() != secondStart {
		t.Fatalf("position = %d, want %d", scanner.Position(), secondStart)
	}
	second, err := scanner.Next()
	if err != nil {
		t.Fatal(err)
	}
	gotPayload, err := io.ReadAll(second.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, secondPayload) {
		t.Fatalf("second payload = %q", gotPayload)
	}
	if scanner.Position() != int64(len(input)) {
		t.Fatalf("final position = %d, want %d", scanner.Position(), len(input))
	}
}

func TestStrictScannerEmptyBody(t *testing.T) {
	for _, crc := range []bool{false, true} {
		input := encodeStrictBlock(strictBlockSpec{
			blockType: "PGP MESSAGE",
			payload:   nil,
			crc:       crc,
		}, "\r\n")
		scanner, err := NewScanner(&oneByteReader{in: input}, CRCVerifyIfPresent)
		if err != nil {
			t.Fatal(err)
		}
		block, err := scanner.Next()
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(block.Body)
		if err != nil || len(payload) != 0 {
			t.Fatalf("payload=%x, err=%v", payload, err)
		}
		if scanner.Position() != int64(len(input)) {
			t.Fatalf("position=%d, want %d", scanner.Position(), len(input))
		}
	}
}

func TestStrictScannerCRCPolicies(t *testing.T) {
	tests := []struct {
		name      string
		policy    CRCPolicy
		crc       bool
		badCRC    bool
		blockType string
		wantError bool
	}{
		{"ignore accepts missing", CRCIgnore, false, false, "PGP SIGNATURE", false},
		{"ignore accepts bad", CRCIgnore, true, true, "PGP SIGNATURE", false},
		{"verify accepts missing", CRCVerifyIfPresent, false, false, "PGP SIGNATURE", false},
		{"verify accepts good", CRCVerifyIfPresent, true, false, "PGP SIGNATURE", false},
		{"verify rejects bad", CRCVerifyIfPresent, true, true, "PGP SIGNATURE", true},
		{"require rejects missing", CRCRequire, false, false, "PGP SIGNATURE", true},
		{"require accepts good", CRCRequire, true, false, "PGP SIGNATURE", false},
		{"forbidden type rejects CRC under ignore", CRCIgnore, true, false, "X-CUSTOM", true},
		{"forbidden type accepts missing under require", CRCRequire, false, false, "X-CUSTOM", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := encodeStrictBlock(strictBlockSpec{
				blockType: test.blockType,
				payload:   []byte("payload"),
				crc:       test.crc,
				badCRC:    test.badCRC,
			}, "\n")
			scanner, err := NewScanner(bytes.NewReader(input), test.policy)
			if err != nil {
				t.Fatal(err)
			}
			block, err := scanner.Next()
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(block.Body)
			if test.wantError && err == nil {
				t.Fatal("ReadAll succeeded")
			}
			if !test.wantError && err != nil {
				t.Fatalf("ReadAll = %v", err)
			}
		})
	}
}

func TestStrictScannerErrorsDoNotConsumeNextBlock(t *testing.T) {
	tests := []struct {
		name       string
		spec       strictBlockSpec
		wantOffset string
	}{
		{
			name: "bad base64",
			spec: strictBlockSpec{
				blockType: "PGP SIGNATURE",
				payload:   []byte("payload"),
				badBase64: true,
			},
			wantOffset: "!bad",
		},
		{
			name: "bad CRC",
			spec: strictBlockSpec{
				blockType: "PGP SIGNATURE",
				payload:   []byte("payload"),
				crc:       true,
				badCRC:    true,
			},
			wantOffset: "=AAAA",
		},
		{
			name: "missing END",
			spec: strictBlockSpec{
				blockType: "PGP SIGNATURE",
				payload:   []byte("payload"),
				crc:       true,
				noEnd:     true,
			},
			wantOffset: "",
		},
		{
			name: "wrong END type",
			spec: strictBlockSpec{
				blockType: "PGP SIGNATURE",
				payload:   []byte("payload"),
				wrongEnd:  "PGP MESSAGE",
			},
			wantOffset: "-----END PGP MESSAGE-----",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := encodeStrictBlock(test.spec, "\n")
			nextBlock := []byte("\n-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----\n")
			input = append(input, nextBlock...)

			scanner, err := NewScanner(&oneByteReader{in: input}, CRCVerifyIfPresent)
			if err != nil {
				t.Fatal(err)
			}
			block, err := scanner.Next()
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "bad base64" {
				if _, err = io.ReadAll(block.Body); err == nil {
					t.Fatal("expected syntax error")
				}
			} else {
				body := make([]byte, len(test.spec.payload))
				if _, err = io.ReadFull(block.Body, body); err != nil {
					t.Fatal(err)
				}
				if _, err = block.Body.Read(make([]byte, 1)); err == nil {
					t.Fatal("expected syntax error")
				}
			}

			nextStart := int64(strings.Index(string(input), "-----BEGIN PGP MESSAGE-----"))
			if scanner.Position() > nextStart {
				t.Fatalf("position = %d consumed next block at %d", scanner.Position(), nextStart)
			}
			if test.wantOffset != "" {
				want := int64(strings.Index(string(input), test.wantOffset))
				if scanner.Position() < want {
					t.Fatalf("position = %d, expected at or after %d", scanner.Position(), want)
				}
			}
			if _, err = scanner.Next(); err == nil {
				t.Fatal("scanner recovered by searching malformed block data")
			}
		})
	}
}

func TestStrictScannerMalformedBegin(t *testing.T) {
	input := []byte("-----BEGIN PGP SIGNATURE\r\n\r\ncGF5bG9hZA==\r\n-----END PGP SIGNATURE-----\r\n")
	scanner, err := NewScanner(bytes.NewReader(input), CRCVerifyIfPresent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = scanner.Next(); err == nil {
		t.Fatal("malformed BEGIN line was accepted")
	}
	if _, err = scanner.Next(); err == nil {
		t.Fatal("scanner recovered after a malformed BEGIN line")
	}
}

func encodeStrictBlock(spec strictBlockSpec, newline string) []byte {
	var block bytes.Buffer
	block.WriteString("-----BEGIN ")
	block.WriteString(spec.blockType)
	block.WriteString("-----")
	block.WriteString(newline)

	for _, header := range spec.headers {
		block.WriteString(header.Key)
		block.WriteString(": ")
		block.WriteString(header.Value)
		block.WriteString(newline)
	}
	block.WriteString(newline)

	if len(spec.payload) > 0 {
		encoded := base64.StdEncoding.EncodeToString(spec.payload)
		if spec.badBase64 {
			block.WriteString("!bad")
			block.WriteString(newline)
		} else {
			for len(encoded) > 0 {
				line := encoded
				if len(line) > 64 {
					line = line[:64]
					encoded = encoded[64:]
				} else {
					encoded = ""
				}
				block.WriteString(line)
				block.WriteString(newline)
			}
		}
	}

	if spec.crc {
		if spec.badCRC {
			block.WriteString("=AAAA")
		} else {
			crc := crc24(crc24Init, spec.payload)
			var checksum [3]byte
			checksum[0] = byte(crc >> 16)
			checksum[1] = byte(crc >> 8)
			checksum[2] = byte(crc)
			var encoded [4]byte
			base64.StdEncoding.Encode(encoded[:], checksum[:])
			block.WriteString("=")
			block.Write(encoded[:])
		}
		block.WriteString(newline)
	}

	if !spec.noEnd {
		endType := spec.blockType
		if spec.wrongEnd != "" {
			endType = spec.wrongEnd
		}
		block.WriteString("-----END ")
		block.WriteString(endType)
		block.WriteString("-----")
		block.WriteString(newline)
	}
	return block.Bytes()
}
