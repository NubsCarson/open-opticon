package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

// golden is the exact deterministic-CBOR payload from test_payload.c:
// {version:1, nonce:AABB, event:2, voice:false, presence:1, frames:10,
//
//	window_ms:160, counter:7, config_hash:0x11*32}
var golden = mustHex(
	"a9" +
		"0001" +
		"0142aabb" +
		"0202" +
		"03f4" +
		"0401" +
		"050a" +
		"0618a0" +
		"0707" +
		"085820" +
		"1111111111111111111111111111111111111111111111111111111111111111")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestDecodePayloadGolden(t *testing.T) {
	p, err := DecodePayload(golden)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Version != 1 {
		t.Errorf("version = %d, want 1", p.Version)
	}
	if hex.EncodeToString(p.Nonce) != "aabb" {
		t.Errorf("nonce = %x, want aabb", p.Nonce)
	}
	if p.EventID != EventAlarmTone {
		t.Errorf("event = %d, want %d", p.EventID, EventAlarmTone)
	}
	if p.VoiceActive {
		t.Error("voice_active = true, want false")
	}
	if p.Presence != 1 {
		t.Errorf("presence = %d, want 1", p.Presence)
	}
	if p.Frames != 10 || p.WindowMs != 160 || p.Counter != 7 {
		t.Errorf("frames/window/counter = %d/%d/%d, want 10/160/7",
			p.Frames, p.WindowMs, p.Counter)
	}
	if len(p.ConfigHash) != 32 {
		t.Errorf("config_hash len = %d, want 32", len(p.ConfigHash))
	}
	if p.EventName() != "alarm_tone" {
		t.Errorf("event name = %q", p.EventName())
	}
}

func TestDecodeRejectsTrailingBytes(t *testing.T) {
	bad := append(append([]byte{}, golden...), 0x00)
	if _, err := DecodePayload(bad); err == nil {
		t.Error("expected error on trailing bytes")
	}
}

const cfg32 = "1111111111111111111111111111111111111111111111111111111111111111"

func TestDecodeRejectsNonMinimalInt(t *testing.T) {
	// version=1 re-encoded in the 1-byte form (0x18 0x01) instead of 0x01.
	bad := mustHex("a9" + "001801" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + cfg32)
	if _, err := DecodePayload(bad); err == nil {
		t.Error("expected error on non-minimal integer encoding")
	}
}

func TestDecodeRejectsOutOfOrderKeys(t *testing.T) {
	// map(2) with keys [1,0] — descending.
	bad := mustHex("a2" + "0101" + "0001")
	if _, err := DecodePayload(bad); err == nil {
		t.Error("expected error on out-of-order keys")
	}
}

func TestDecodeRejectsDuplicateKeys(t *testing.T) {
	// map(2) with key 0 twice.
	bad := mustHex("a2" + "0001" + "0002")
	if _, err := DecodePayload(bad); err == nil {
		t.Error("expected error on duplicate key")
	}
}

func TestDecodeRejectsMissingKeys(t *testing.T) {
	// map(1) with only version present.
	bad := mustHex("a1" + "0001")
	if _, err := DecodePayload(bad); err == nil {
		t.Error("expected error on missing required keys")
	}
}

// signGolden signs SHA-256(payload) and returns a Bundle + the pub coords.
func signGolden(t *testing.T, payload []byte) (Bundle, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	px := key.PublicKey.X.Bytes()
	py := key.PublicKey.Y.Bytes()
	// left-pad to 32 bytes
	px = leftPad(px, 32)
	py = leftPad(py, 32)
	b := Bundle{
		Schema:  "honest-ear/bound-output/v1",
		Payload: hex.EncodeToString(payload),
		Sig:     hex.EncodeToString(sig),
		PubX:    hex.EncodeToString(px),
		PubY:    hex.EncodeToString(py),
	}
	return b, px, py
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func TestVerifyHappyPath(t *testing.T) {
	b, px, py := signGolden(t, golden)
	res := VerifyBundle(b, Options{
		ExpectedNonce: mustHex("aabb"),
		PinPubX:       px,
		PinPubY:       py,
		LastCounter:   6, // golden counter is 7
	})
	if !res.OK {
		t.Fatalf("expected OK, got: %s", res.Reason)
	}
	if res.Predicate.EventName() != "alarm_tone" {
		t.Errorf("event = %s", res.Predicate.EventName())
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	b, _, _ := signGolden(t, golden)
	// Flip one payload byte AFTER signing -> signature must fail.
	tampered := append([]byte{}, golden...)
	tampered[1] ^= 0xff
	b.Payload = hex.EncodeToString(tampered)
	res := VerifyBundle(b, Options{ExpectedNonce: mustHex("aabb")})
	if res.OK {
		t.Error("tampered payload verified; must fail")
	}
}

func TestVerifyRejectsStaleNonce(t *testing.T) {
	b, _, _ := signGolden(t, golden)
	res := VerifyBundle(b, Options{ExpectedNonce: mustHex("ccdd")})
	if res.OK {
		t.Error("nonce mismatch verified; must fail")
	}
	if res.Reason == "" {
		t.Error("expected a reason")
	}
}

func TestVerifyRejectsReplayCounter(t *testing.T) {
	b, _, _ := signGolden(t, golden)
	res := VerifyBundle(b, Options{
		ExpectedNonce: mustHex("aabb"),
		LastCounter:   7, // equal -> not strictly greater
	})
	if res.OK {
		t.Error("replayed counter verified; must fail")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	b, _, _ := signGolden(t, golden)
	// Replace pub key with a different valid P-256 point.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b.PubX = hex.EncodeToString(leftPad(other.PublicKey.X.Bytes(), 32))
	b.PubY = hex.EncodeToString(leftPad(other.PublicKey.Y.Bytes(), 32))
	res := VerifyBundle(b, Options{ExpectedNonce: mustHex("aabb")})
	if res.OK {
		t.Error("wrong key verified; must fail")
	}
}

func TestVerifyRejectsOffCurveKey(t *testing.T) {
	b, _, _ := signGolden(t, golden)
	b.PubX = hex.EncodeToString(leftPad(big.NewInt(1).Bytes(), 32))
	b.PubY = hex.EncodeToString(leftPad(big.NewInt(1).Bytes(), 32))
	res := VerifyBundle(b, Options{ExpectedNonce: mustHex("aabb")})
	if res.OK {
		t.Error("off-curve key verified; must fail")
	}
}

func TestVerifyRejectsPinMismatch(t *testing.T) {
	b, px, _ := signGolden(t, golden)
	res := VerifyBundle(b, Options{
		ExpectedNonce: mustHex("aabb"),
		PinPubX:       px,
		PinPubY:       mustHex("00000000000000000000000000000000000000000000000000000000000000ff"),
	})
	if res.OK {
		t.Error("pin mismatch verified; must fail")
	}
}

// FuzzDecodePayload asserts the CBOR reader never panics and never returns a
// (nil, nil) result on arbitrary input — it must always fail closed with an
// error rather than crash or half-decode. The seed corpus runs under plain
// `go test`; fuzz deeper with: go test -run x -fuzz FuzzDecodePayload ./...
func FuzzDecodePayload(f *testing.F) {
	f.Add(golden)
	f.Add([]byte{})
	f.Add([]byte{0xa9})                           // map header, no entries
	f.Add(mustHex("a90001"))                      // truncated map
	f.Add(mustHex("a1" + "001b0000000000000001")) // 1-entry map, 8-byte uint
	f.Add(mustHex("0101"))                        // not a map at all
	f.Add(mustHex("a90142ffff"))                  // bstr len overruns buffer
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodePayload(b) // must not panic
		if err == nil && p == nil {
			t.Fatal("nil predicate with nil error")
		}
	})
}
