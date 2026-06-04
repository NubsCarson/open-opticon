package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

const zero32 = "0000000000000000000000000000000000000000000000000000000000000000"

// chainPayload builds an 11-key golden payload identical to `golden` except the
// monotonic counter (must be < 24 for single-byte encoding) and the prev_digest
// (32-byte hex). Used to exercise the stream hash-chain (Gate 4).
func chainPayload(counter byte, prevHex string) []byte {
	return mustHex("ab" + "0001" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "07" + fmt.Sprintf("%02x", counter) +
		"085820" + cfg32 + "095820" + inp32 + "0a5820" + prevHex)
}

// golden is the exact deterministic-CBOR payload from test_payload.c:
// {version:1, nonce:AABB, event:2, voice:false, presence:1, frames:10,
//
//	window_ms:160, counter:7, config_hash:0x11*32, input_hash:0x22*32,
//	prev_digest:0x33*32}
var golden = mustHex(
	"ab" +
		"0001" +
		"0142aabb" +
		"0202" +
		"03f4" +
		"0401" +
		"050a" +
		"0618a0" +
		"0707" +
		"085820" + cfg32 +
		"095820" + inp32 +
		"0a5820" + prev32)

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
const inp32 = "2222222222222222222222222222222222222222222222222222222222222222"
const prev32 = "3333333333333333333333333333333333333333333333333333333333333333"

func TestDecodeRejectsNonMinimalInt(t *testing.T) {
	// version=1 re-encoded in the 1-byte form (0x18 0x01) instead of 0x01.
	bad := mustHex("ab" + "001801" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + cfg32 + "095820" + inp32 + "0a5820" + prev32)
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

// The C encoder caps the nonce at HE_NONCE_MAX (64); a 65-byte nonce is a
// payload no genuine device could produce, so the decoder must reject it even
// though it is well-formed CBOR.
func TestDecodeRejectsOversizeNonce(t *testing.T) {
	nonce65 := hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 65)) // 0x58 0x41 = bstr(65)
	bad := mustHex("ab" + "0001" + "01" + "5841" + nonce65 + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + cfg32 + "095820" + inp32 + "0a5820" + prev32)
	if _, err := DecodePayload(bad); err == nil {
		t.Error("expected error on nonce longer than NonceMax")
	}
}

// The three digests are always SHA-256 (32 bytes); a short/long digest is
// non-conformant and must be rejected at decode.
func TestDecodeRejectsWrongHashLength(t *testing.T) {
	h16 := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 16)) // 0x50 = bstr(16)
	bad := mustHex("ab" + "0001" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "0850" + h16 + "095820" + inp32 + "0a5820" + prev32)
	if _, err := DecodePayload(bad); err == nil {
		t.Error("expected error on config_hash != 32 bytes")
	}
}

// signWith signs SHA-256(payload) with key and returns the on-the-wire Bundle.
func signWith(t *testing.T, payload []byte, key *ecdsa.PrivateKey) Bundle {
	t.Helper()
	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	s = NormalizeLowS(s) // canonical low-s (ecdsa.Sign returns a random s)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return Bundle{
		Schema:  "honest-ear/bound-output/v1",
		Payload: hex.EncodeToString(payload),
		Sig:     hex.EncodeToString(sig),
		PubX:    hex.EncodeToString(leftPad(key.PublicKey.X.Bytes(), 32)),
		PubY:    hex.EncodeToString(leftPad(key.PublicKey.Y.Bytes(), 32)),
	}
}

// signGolden signs SHA-256(payload) with a fresh key and returns the Bundle + pub coords.
func signGolden(t *testing.T, payload []byte) (Bundle, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signWith(t, payload, key),
		leftPad(key.PublicKey.X.Bytes(), 32), leftPad(key.PublicKey.Y.Bytes(), 32)
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// Gate 1b: a malleated high-s device signature (still a valid ECDSA sig over
// the same payload) must be rejected, exactly as the on-chain OZ P256 verifier
// rejects it — so the host/WASM verifier and the chain never disagree.
func TestVerifyRejectsHighS(t *testing.T) {
	b, px, py := signGolden(t, golden) // canonical low-s
	sig, err := hex.DecodeString(b.Sig)
	if err != nil || len(sig) != 64 {
		t.Fatalf("bad sig fixture: %v", err)
	}
	if !lowS(sig) {
		t.Fatal("signGolden should emit canonical low-s")
	}
	s := new(big.Int).SetBytes(sig[32:])
	new(big.Int).Sub(elliptic.P256().Params().N, s).FillBytes(sig[32:]) // s -> N-s (high-s)
	b.Sig = hex.EncodeToString(sig)
	res := VerifyBundle(b, Options{
		ExpectedNonce: mustHex("aabb"),
		PinPubX:       px,
		PinPubY:       py,
		LastCounter:   6,
	})
	if res.OK {
		t.Fatal("VerifyBundle accepted a high-s (malleated) device signature; want rejection")
	}
}

func TestNormalizeLowS(t *testing.T) {
	N := elliptic.P256().Params().N
	half := new(big.Int).Rsh(N, 1)
	if lo := big.NewInt(12345); NormalizeLowS(lo).Cmp(lo) != 0 {
		t.Fatal("a low-s value must be returned unchanged")
	}
	hi := new(big.Int).Add(half, big.NewInt(1)) // just above N/2 -> high-s
	got := NormalizeLowS(hi)
	if got.Cmp(half) > 0 {
		t.Fatal("normalized value is still high-s")
	}
	if got.Cmp(new(big.Int).Sub(N, hi)) != 0 {
		t.Fatal("high-s must map to N - s")
	}
}

// Signers must emit canonical low-s, so a device bundle is accepted identically
// by this verifier and the on-chain OpenZeppelin P256 verifier (which rejects
// high-s for malleability). Guards both Go signing paths — raw (signWith) and
// COSE_Sign1 (SignCOSESign1). ecdsa.Sign returns a random s, so without
// normalization ~half of 20 iterations would be high-s.
func TestGoSignersEmitLowS(t *testing.T) {
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	isLowS := func(sig []byte) bool { return new(big.Int).SetBytes(sig[32:]).Cmp(half) <= 0 }
	for i := 0; i < 20; i++ {
		b, _, _ := signGolden(t, golden)
		raw, err := hex.DecodeString(b.Sig)
		if err != nil || len(raw) != 64 {
			t.Fatalf("bad raw sig: %v", err)
		}
		if !isLowS(raw) {
			t.Fatalf("signWith emitted high-s on iter %d", i)
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := SignCOSESign1(golden, key)
		if err != nil {
			t.Fatal(err)
		}
		if !isLowS(msg[len(msg)-64:]) { // COSE_Sign1's trailing 64 bytes are r||s
			t.Fatalf("SignCOSESign1 emitted high-s on iter %d", i)
		}
	}
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

// An empty (zero-length) nonce must NOT silently disable the freshness gate.
// Before the len()==0 guard, an empty expected nonce "matched" an empty payload
// nonce (ConstantTimeCompare([]byte{},[]byte{})==1), a fail-open reachable via
// he-gui's client-controlled nonce="" + a payload signed by the published key.
func TestVerifyRejectsEmptyNonceFailOpen(t *testing.T) {
	// Same golden payload but with an EMPTY nonce bstr (0140, not 0142aabb).
	emptyNonce := mustHex(
		"ab" + "0001" + "0140" + "0202" + "03f4" + "0401" + "050a" + "0618a0" +
			"0707" + "085820" + cfg32 + "095820" + inp32 + "0a5820" + prev32)
	b, _, _ := signGolden(t, emptyNonce) // valid signature, so only freshness is on trial
	for name, opt := range map[string]Options{
		"empty expected nonce": {ExpectedNonce: []byte{}},
		"nil expected nonce":   {ExpectedNonce: nil},
		"real vs empty nonce":  {ExpectedNonce: mustHex("aabb")},
	} {
		if VerifyBundle(b, opt).OK {
			t.Errorf("FAIL-OPEN: accepted with %s; freshness gate bypassed", name)
		}
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

func TestVerifyRejectsWrongVersion(t *testing.T) {
	// golden with the version value re-encoded as 2 (key 0 -> 2): "0001" -> "0002".
	v2 := mustHex("ab" + "0002" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + cfg32 + "095820" + inp32 + "0a5820" + prev32)
	b, _, _ := signGolden(t, v2)
	res := VerifyBundle(b, Options{ExpectedNonce: mustHex("aabb")})
	if res.OK {
		t.Error("payload with unsupported version verified; must fail")
	}
}

func TestVerifyRejectsNilExpectedNonce(t *testing.T) {
	b, _, _ := signGolden(t, golden)
	res := VerifyBundle(b, Options{}) // ExpectedNonce nil
	if res.OK {
		t.Error("verify with no expected nonce passed; must fail")
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

// TestVerifyChainContinuity exercises Gate 4: a genesis bundle (prev_digest =
// zeros) chains to sha256(payload); the next window must carry that digest as
// its prev_digest. A suppressed/forked window breaks the chain and is rejected.
func TestVerifyChainContinuity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	px := leftPad(key.PublicKey.X.Bytes(), 32)
	py := leftPad(key.PublicKey.Y.Bytes(), 32)

	// Genesis window: prev_digest = 32 zero bytes, counter 1.
	genesis := chainPayload(1, zero32)
	bGen := signWith(t, genesis, key)
	resGen := VerifyBundle(bGen, Options{
		ExpectedNonce:      mustHex("aabb"),
		PinPubX:            px,
		PinPubY:            py,
		LastCounter:        0,
		ExpectedPrevDigest: mustHex(zero32), // genesis must chain from zeros
	})
	if !resGen.OK {
		t.Fatalf("genesis: %s", resGen.Reason)
	}
	want := sha256.Sum256(genesis)
	if !bytes.Equal(resGen.NextDigest, want[:]) {
		t.Fatalf("NextDigest = %x, want sha256(payload) = %x", resGen.NextDigest, want[:])
	}

	// Window 2: prev_digest = genesis's NextDigest, counter 2 -> verifies.
	win2 := chainPayload(2, hex.EncodeToString(resGen.NextDigest))
	b2 := signWith(t, win2, key)
	res2 := VerifyBundle(b2, Options{
		ExpectedNonce:      mustHex("aabb"),
		PinPubX:            px,
		PinPubY:            py,
		LastCounter:        1,
		ExpectedPrevDigest: resGen.NextDigest,
	})
	if !res2.OK {
		t.Fatalf("window2: %s", res2.Reason)
	}

	// Gap detection: the verifier expects window2's NextDigest as the next
	// prev_digest, but a suppressed window means it is shown a payload whose
	// prev_digest doesn't match -> chain break, must fail.
	resGap := VerifyBundle(b2, Options{
		ExpectedNonce:      mustHex("aabb"),
		PinPubX:            px,
		PinPubY:            py,
		LastCounter:        1,
		ExpectedPrevDigest: res2.NextDigest, // expecting the link AFTER window2
	})
	if resGap.OK {
		t.Error("chain gap (suppressed window) accepted; must fail")
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
	// Format-change (key 9 input_hash, key 10 prev_digest) + canonicality surface:
	f.Add(mustHex("a9" + "0001" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + cfg32)) // old 9-key (missing input+prev) -> reject
	f.Add(mustHex("aa" + "0001" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + cfg32 + "095820" + inp32)) // old 10-key (missing prev_digest) -> reject
	f.Add(mustHex("a2" + "0202" + "0001")) // out-of-order keys -> reject (non-canonical)
	f.Add(mustHex("a2" + "0001" + "0001")) // duplicate key -> reject
	f.Add(mustHex("a1" + "00" + "1800"))   // non-minimal uint (0 as 1-byte) -> reject
	f.Add(mustHex("aa" + "0001" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" +
		"1111111111111111111111111111111111111111111111111111111111111111" +
		"0950" + "2222222222222222222222222222222222")) // key 9 wrong bstr len (16, not 32)
	f.Add(mustHex("ab" + "0001" + "01" + "5841" + hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 65)) +
		"0202" + "03f4" + "0401" + "050a" + "0618a0" + "0707" + "085820" + cfg32 +
		"095820" + inp32 + "0a5820" + prev32)) // nonce 65 > NonceMax -> reject
	f.Add(mustHex("ab" + "0001" + "0142aabb" + "0202" + "03f4" + "0401" + "050a" + "0618a0" +
		"0707" + "0850" + hex.EncodeToString(bytes.Repeat([]byte{0x11}, 16)) +
		"095820" + inp32 + "0a5820" + prev32)) // config_hash 16 != 32 -> reject
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodePayload(b) // must not panic on ANY input
		if err == nil && p == nil {
			t.Fatal("nil predicate with nil error")
		}
		if err == nil {
			// A successful decode must be deterministic + re-decode identically.
			if _, err2 := DecodePayload(b); err2 != nil {
				t.Fatalf("decode non-deterministic: ok then %v", err2)
			}
		}
	})
}
