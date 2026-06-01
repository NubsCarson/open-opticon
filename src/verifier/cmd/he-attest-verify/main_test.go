package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	verifier "honest-ear/verifier"
)

func TestReadTokenRawHexString(t *testing.T) {
	got := readToken("d2844340")
	want := []byte{0xd2, 0x84, 0x43, 0x40}
	if !bytes.Equal(got, want) {
		t.Errorf("readToken(hex) = %x, want %x", got, want)
	}
}

func TestReadTokenFileWithHex(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tok.hex")
	if err := os.WriteFile(p, []byte("d2844340\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readToken(p)
	if !bytes.Equal(got, []byte{0xd2, 0x84, 0x43, 0x40}) {
		t.Errorf("readToken(file-hex) = %x", got)
	}
}

func TestReadTokenFileWithRawBytes(t *testing.T) {
	// A file whose contents are NOT valid hex must be returned as raw bytes.
	p := filepath.Join(t.TempDir(), "tok.bin")
	raw := []byte{0xd2, 0x84, 0x43, 0x40, 0x7a} // odd length as hex text -> not hex
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got := readToken(p)
	if !bytes.Equal(got, raw) {
		t.Errorf("readToken(file-raw) = %x, want %x", got, raw)
	}
}

func TestPrintClaims(t *testing.T) {
	c := &verifier.PSAClaims{
		Profile:          verifier.PSAProfile,
		Nonce:            []byte{0xca, 0xfe},
		ImplementationID: []byte("impl"),
		SoftwareComponents: []verifier.SWComponent{
			{MeasurementType: "PRoT", MeasurementValue: []byte{0xab, 0xcd}, SignerID: []byte{0x11}},
		},
	}
	var out bytes.Buffer
	printClaims(&out, c)
	s := out.String()
	for _, want := range []string{verifier.PSAProfile, "cafe", "PRoT", "abcd", "eat_profile"} {
		if !strings.Contains(s, want) {
			t.Errorf("printClaims output missing %q\n%s", want, s)
		}
	}
}
