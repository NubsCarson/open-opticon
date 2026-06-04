package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

// signCOSE signs the COSE Sig_structure over `payload` with key and returns the
// on-the-wire COSEBundle.
func signCOSE(t *testing.T, payload []byte, key *ecdsa.PrivateKey) COSEBundle {
	t.Helper()
	msg, err := SignCOSESign1(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	return COSEBundle{
		Schema: "honest-ear/cose-sign1/v1",
		COSE:   hex.EncodeToString(msg),
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

// Gate 1b on the COSE envelope: a malleated high-s device signature (still a
// valid ECDSA sig over the same Sig_structure) must be rejected, just as the
// raw envelope and the on-chain verifier reject it.
func TestVerifyCOSERejectsHighS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := signCOSE(t, golden, key) // SignCOSESign1 emits canonical low-s
	raw := mustHex(b.COSE)
	// COSE_Sign1's trailing 64 bytes are r||s; malleate s -> N-s (high-s).
	s := new(big.Int).SetBytes(raw[len(raw)-32:])
	new(big.Int).Sub(elliptic.P256().Params().N, s).FillBytes(raw[len(raw)-32:])
	b.COSE = hex.EncodeToString(raw)
	res := VerifyCOSEBundle(b, Options{
		ExpectedNonce: mustHex("aabb"),
		PinPubX:       leftPad(key.PublicKey.X.Bytes(), 32),
		PinPubY:       leftPad(key.PublicKey.Y.Bytes(), 32),
		LastCounter:   6,
	})
	if res.OK {
		t.Fatal("VerifyCOSEBundle accepted a high-s (malleated) COSE device signature; want rejection")
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

// bstrHead must use the smallest correct CBOR head at each size class and never
// truncate the length (the >=64KiB 4-byte form was the fix).
func TestBstrHeadNoTruncation(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x40}},
		{23, []byte{0x57}},
		{24, []byte{0x58, 24}},
		{255, []byte{0x58, 255}},
		{256, []byte{0x59, 0x01, 0x00}},
		{65535, []byte{0x59, 0xff, 0xff}},
		{65536, []byte{0x5a, 0x00, 0x01, 0x00, 0x00}}, // was silently truncated before
	}
	for _, c := range cases {
		if got := bstrHead(c.n); !bytes.Equal(got, c.want) {
			t.Errorf("bstrHead(%d) = %x, want %x", c.n, got, c.want)
		}
	}
}

// COSEPayload extracts the inner payload of a COSE_Sign1 (parsing only, no crypto) —
// used by he-dump to decode a COSE bundle. Round-trips with SignCOSESign1; rejects
// non-COSE bytes rather than panicking.
func TestCOSEPayloadRoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg, err := SignCOSESign1(golden, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := COSEPayload(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("COSEPayload: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Errorf("COSEPayload round-trip mismatch: got %x, want %x", got, golden)
	}
	if _, err := COSEPayload("00"); err == nil {
		t.Error("COSEPayload accepted non-COSE bytes")
	}
	if _, err := COSEPayload("zz"); err == nil {
		t.Error("COSEPayload accepted invalid hex")
	}
}
