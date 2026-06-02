package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// --- minimal CBOR builders for minting a faithful PSA token in tests ---

func cbHead(major byte, n uint64) []byte {
	mt := major << 5
	switch {
	case n < 24:
		return []byte{mt | byte(n)}
	case n < 256:
		return []byte{mt | 24, byte(n)}
	case n < 65536:
		return []byte{mt | 25, byte(n >> 8), byte(n)}
	default:
		return []byte{mt | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func cbUint(n uint64) []byte  { return cbHead(0, n) }
func cbBytes(b []byte) []byte { return append(cbHead(2, uint64(len(b))), b...) }
func cbText(s string) []byte  { return append(cbHead(3, uint64(len(s))), []byte(s)...) }

// psaClaims builds a PSA claims map with one software component.
func psaClaims(profile string, nonce, instanceID, implID, measurement, signerID []byte) []byte {
	var b []byte
	b = append(b, cbHead(5, 5)...) // map(5)
	b = append(b, cbUint(psaKeyProfile)...)
	b = append(b, cbText(profile)...)
	b = append(b, cbUint(psaKeyNonce)...)
	b = append(b, cbBytes(nonce)...)
	b = append(b, cbUint(psaKeyInstanceID)...)
	b = append(b, cbBytes(instanceID)...)
	b = append(b, cbUint(psaKeyImplementation)...)
	b = append(b, cbBytes(implID)...)
	b = append(b, cbUint(psaKeySoftware)...)
	b = append(b, cbHead(4, 1)...) // array(1)
	b = append(b, cbHead(5, 3)...) // component map(3)
	b = append(b, cbUint(swKeyMeasurementType)...)
	b = append(b, cbText("PRoT")...)
	b = append(b, cbUint(swKeyMeasurementValue)...)
	b = append(b, cbBytes(measurement)...)
	b = append(b, cbUint(swKeySignerID)...)
	b = append(b, cbBytes(signerID)...)
	return b
}

// mintToken builds a COSE_Sign1 (ES256) over the given claims payload, signed by
// key — i.e. a faithful PSA attestation token for testing the verifier. Uses the
// production COSE encoder (SignCOSESign1), so the test mints exactly what the
// verifier accepts.
func mintToken(t *testing.T, payload []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	msg, err := SignCOSESign1(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestVerifyPSATokenHappyPath(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	px, py := PubXY(key)
	nonce := mustHex("cafef00dcafef00d")
	meas := bytes.Repeat([]byte{0xAB}, 32)
	signer := bytes.Repeat([]byte{0xCD}, 32)
	claims := psaClaims(PSAProfile, nonce, []byte("instance-0001"), []byte("qemu-optee-ra-01"), meas, signer)
	token := mintToken(t, claims, key)

	c, err := VerifyPSAToken(token, px, py, PSAOptions{
		ExpectedNonce:         nonce,
		ReferenceMeasurements: [][]byte{meas},
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Profile != PSAProfile {
		t.Errorf("profile = %q", c.Profile)
	}
	if len(c.SoftwareComponents) != 1 || !bytes.Equal(c.SoftwareComponents[0].MeasurementValue, meas) {
		t.Errorf("software components = %+v", c.SoftwareComponents)
	}
	if !bytes.Equal(c.Nonce, nonce) {
		t.Errorf("nonce = %x", c.Nonce)
	}
}

func TestVerifyPSATokenRejectsWrongNonce(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	px, py := PubXY(key)
	meas := bytes.Repeat([]byte{0xAB}, 32)
	claims := psaClaims(PSAProfile, mustHex("aaaa"), []byte("i"), []byte("impl"), meas, []byte("s"))
	token := mintToken(t, claims, key)
	if _, err := VerifyPSAToken(token, px, py, PSAOptions{ExpectedNonce: mustHex("bbbb"), ReferenceMeasurements: [][]byte{meas}}); err == nil {
		t.Error("wrong nonce accepted; must fail")
	}
}

func TestVerifyPSATokenRejectsUnknownMeasurement(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	px, py := PubXY(key)
	meas := bytes.Repeat([]byte{0xAB}, 32)
	claims := psaClaims(PSAProfile, mustHex("aaaa"), []byte("i"), []byte("impl"), meas, []byte("s"))
	token := mintToken(t, claims, key)
	// Reference set does NOT contain the token's measurement -> appraisal fails.
	other := bytes.Repeat([]byte{0x99}, 32)
	if _, err := VerifyPSAToken(token, px, py, PSAOptions{ExpectedNonce: mustHex("aaaa"), ReferenceMeasurements: [][]byte{other}}); err == nil {
		t.Error("unpublished measurement accepted; must fail")
	}
}

func TestVerifyPSATokenRejectsWrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	meas := bytes.Repeat([]byte{0xAB}, 32)
	claims := psaClaims(PSAProfile, mustHex("aaaa"), []byte("i"), []byte("impl"), meas, []byte("s"))
	token := mintToken(t, claims, key)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ox, oy := PubXY(other)
	if _, err := VerifyPSAToken(token, ox, oy, PSAOptions{ExpectedNonce: mustHex("aaaa"), ReferenceMeasurements: [][]byte{meas}}); err == nil {
		t.Error("token verified under wrong key; must fail")
	}
}

func TestVerifyPSATokenRejectsTamper(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	px, py := PubXY(key)
	meas := bytes.Repeat([]byte{0xAB}, 32)
	claims := psaClaims(PSAProfile, mustHex("aaaa"), []byte("i"), []byte("impl"), meas, []byte("s"))
	token := mintToken(t, claims, key)
	token[30] ^= 0xff // flip a byte inside the claims payload
	if _, err := VerifyPSAToken(token, px, py, PSAOptions{ExpectedNonce: mustHex("aaaa"), ReferenceMeasurements: [][]byte{meas}}); err == nil {
		t.Error("tampered token verified; must fail")
	}
}

// A claims map whose software-components array header claims a huge count must be
// rejected by the bounds guard, not drive a giant allocation (DoS). Exercises the
// parser directly since the signature gate sits in front of it on the full path.
func TestParsePSAClaimsRejectsHugeComponentArray(t *testing.T) {
	var b []byte
	b = append(b, cbHead(5, 1)...)           // claims map(1)
	b = append(b, cbUint(psaKeySoftware)...) // key 2399
	b = append(b, cbHead(4, 1_000_000)...)   // array claiming 1e6 components, buffer is tiny
	if _, err := parsePSAClaims(b); err == nil {
		t.Error("huge software-components count accepted; must be bounded")
	}
}

func TestVerifyPSATokenRejectsWrongProfile(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	px, py := PubXY(key)
	meas := bytes.Repeat([]byte{0xAB}, 32)
	claims := psaClaims("http://example.com/not-psa", mustHex("aaaa"), []byte("i"), []byte("impl"), meas, []byte("s"))
	token := mintToken(t, claims, key)
	if _, err := VerifyPSAToken(token, px, py, PSAOptions{ExpectedNonce: mustHex("aaaa"), ReferenceMeasurements: [][]byte{meas}}); err == nil {
		t.Error("wrong eat_profile accepted; must fail")
	}
}
