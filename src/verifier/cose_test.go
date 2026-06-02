package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// bstrHead returns the CBOR byte-string head for length n (smallest form).
func bstrHead(n int) []byte {
	switch {
	case n < 24:
		return []byte{byte(0x40 | n)}
	case n < 256:
		return []byte{0x58, byte(n)}
	default:
		return []byte{0x59, byte(n >> 8), byte(n)}
	}
}

var coseProtected = []byte{0x43, 0xa1, 0x01, 0x26} // bstr {1:-7} (ES256)

// coseSigStructure mirrors he_cose_sig_structure (the bytes that get signed).
func coseSigStructure(payload []byte) []byte {
	s := []byte{0x84}
	s = append(s, coseContext...)
	s = append(s, coseProtected...)
	s = append(s, 0x40) // external_aad
	s = append(s, bstrHead(len(payload))...)
	s = append(s, payload...)
	return s
}

// coseMessage mirrors he_cose_sign1 (the COSE_Sign1 wire bytes).
func coseMessage(payload, sig []byte) []byte {
	m := []byte{0xd2, 0x84}
	m = append(m, coseProtected...)
	m = append(m, 0xa0) // unprotected {}
	m = append(m, bstrHead(len(payload))...)
	m = append(m, payload...)
	m = append(m, bstrHead(64)...)
	m = append(m, sig...)
	return m
}

// signCOSE signs the COSE Sig_structure over `payload` with key and returns the
// on-the-wire COSEBundle.
func signCOSE(t *testing.T, payload []byte, key *ecdsa.PrivateKey) COSEBundle {
	t.Helper()
	ss := coseSigStructure(payload)
	h := sha256.Sum256(ss)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return COSEBundle{
		Schema: "honest-ear/cose-sign1/v1",
		COSE:   hex.EncodeToString(coseMessage(payload, sig)),
		PubX:   hex.EncodeToString(leftPad(key.PublicKey.X.Bytes(), 32)),
		PubY:   hex.EncodeToString(leftPad(key.PublicKey.Y.Bytes(), 32)),
	}
}

func TestVerifyCOSEHappyPath(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := signCOSE(t, golden, key)
	res := VerifyCOSEBundle(b, Options{
		ExpectedNonce: mustHex("aabb"),
		PinPubX:       leftPad(key.PublicKey.X.Bytes(), 32),
		PinPubY:       leftPad(key.PublicKey.Y.Bytes(), 32),
		LastCounter:   6, // golden counter is 7
	})
	if !res.OK {
		t.Fatalf("expected OK, got: %s", res.Reason)
	}
	if res.Predicate.EventName() != "alarm_tone" {
		t.Errorf("event = %s", res.Predicate.EventName())
	}
	if len(res.NextDigest) != 32 {
		t.Errorf("NextDigest len = %d, want 32", len(res.NextDigest))
	}
}

func TestVerifyCOSERejectsTamperedPayload(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := signCOSE(t, golden, key)
	// Flip one byte of the embedded payload (inside the COSE message) post-signing.
	raw := mustHex(b.COSE)
	// Find the payload region: after d2 84 + protected(4) + a0; payload bstr head.
	// Simpler: flip a byte near the end of the payload region (before the 66-byte
	// signature bstr at the tail: 0x58 0x40 + 64). Flip 10 bytes before that.
	idx := len(raw) - 66 - 10
	raw[idx] ^= 0xff
	b.COSE = hex.EncodeToString(raw)
	if VerifyCOSEBundle(b, Options{ExpectedNonce: mustHex("aabb")}).OK {
		t.Error("tampered COSE payload verified; must fail")
	}
}

func TestVerifyCOSERejectsWrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := signCOSE(t, golden, key)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b.PubX = hex.EncodeToString(leftPad(other.PublicKey.X.Bytes(), 32))
	b.PubY = hex.EncodeToString(leftPad(other.PublicKey.Y.Bytes(), 32))
	if VerifyCOSEBundle(b, Options{ExpectedNonce: mustHex("aabb")}).OK {
		t.Error("wrong key verified; must fail")
	}
}

func TestVerifyCOSERejectsNonES256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := signCOSE(t, golden, key)
	// Corrupt the protected header alg value -7 (0x26) -> -8 (0x27): not ES256.
	raw := mustHex(b.COSE)
	// protected bstr is at offset 2..6 (d2 84 43 a1 01 26); alg byte is index 5.
	if raw[5] != 0x26 {
		t.Fatalf("unexpected protected layout: %x", raw[:7])
	}
	raw[5] = 0x27
	b.COSE = hex.EncodeToString(raw)
	res := VerifyCOSEBundle(b, Options{ExpectedNonce: mustHex("aabb")})
	if res.OK {
		t.Error("non-ES256 alg verified; must fail")
	}
}

func TestVerifyCOSEChainGap(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := signCOSE(t, golden, key) // golden prev_digest is 0x33*32
	// Expecting a different prev_digest -> chain gap -> fail.
	res := VerifyCOSEBundle(b, Options{
		ExpectedNonce:      mustHex("aabb"),
		LastCounter:        6,
		ExpectedPrevDigest: mustHex(zero32),
	})
	if res.OK {
		t.Error("chain gap accepted; must fail")
	}
}

func TestParseCOSERejectsTrailingBytes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := signCOSE(t, golden, key)
	b.COSE = b.COSE + "00"
	if VerifyCOSEBundle(b, Options{ExpectedNonce: mustHex("aabb")}).OK {
		t.Error("trailing bytes accepted; must fail")
	}
}

// A maliciously deep CBOR nesting (a long run of tag bytes) must be REJECTED by
// the recursion cap, not crash the process via stack exhaustion. skipValue is the
// recursive trust-boundary parser reached from VerifyCOSEBundle / VerifyPSAToken.
func TestSkipValueDepthCapRejectsDeepNesting(t *testing.T) {
	// 0xc6 = CBOR tag (major 6); each byte recurses one frame in skipValue.
	deep := make([]byte, maxCBORDepth+50)
	for i := range deep {
		deep[i] = 0xc6
	}
	deep[len(deep)-1] = 0x00 // innermost: a uint(0)
	r := &cborReader{b: deep}
	if err := r.skipValue(); err == nil {
		t.Fatal("deeply nested CBOR was accepted; recursion is unbounded (DoS)")
	}
	// A legitimately shallow item still skips cleanly (cap doesn't over-reject):
	// tag -> array(2) of [uint(1), tstr("hi")].
	shallow := &cborReader{b: []byte{0xc6, 0x82, 0x01, 0x62, 'h', 'i'}}
	if err := shallow.skipValue(); err != nil {
		t.Fatalf("shallow nested CBOR wrongly rejected: %v", err)
	}
}
