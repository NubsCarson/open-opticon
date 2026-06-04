// Package verifier checks Honest Ear "bound-output" bundles.
//
// A bundle ties the detector's minimal output to the same P-256 key whose
// identity is proven by OP-TEE remote attestation. Verification is up to five
// independent gates (gates 0 and 4 are optional); ALL applicable ones must pass:
//
//  0. Endorsement pin (optional): if a public-key pin is supplied, the bundle's
//     key must equal it (constant-time). Ties trust to an enrolled device key.
//  1. Signature: ECDSA-P256 over SHA-256(payload) verifies under the attested
//     public key. (Proves the bytes were produced by the attested enclave key
//     and were not altered by the untrusted host.)
//  2. Freshness: the nonce inside the signed payload equals the fresh nonce
//     the verifier just issued. (Defeats replay / the static-QR swap.)
//  3. Anti-replay: the monotonic counter strictly exceeds the last one seen
//     for this device. (Defeats re-presentation of an old, otherwise-valid
//     bundle within a session.)
//  4. Stream chain (optional): if an expected prev_digest is supplied, the
//     payload must chain onto it, so a suppressed window is detectable.
//
// The same gates 0-4 also verify the COSE_Sign1 envelope (see cose.go); only the
// signed structure differs.
//
// This package is dependency-free (Go stdlib only): it includes a tiny CBOR
// reader for the exact, fixed payload schema (see ../common/he_payload.h).
package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// PayloadVersion is the only schema version this verifier accepts.
const PayloadVersion = 1

// Wire-contract lengths (mirror he_payload.h): the device encoder never emits a
// nonce longer than HE_NONCE_MAX, and the three digests are always SHA-256. The
// decoder enforces these so a payload no genuine device could produce is rejected
// at decode, not silently carried forward.
const (
	NonceMax = 64 // HE_NONCE_MAX
	hashLen  = 32 // SHA-256 digest length (config_hash / input_hash / prev_digest)
)

// Stable payload map keys (mirror he_payload.h).
const (
	keyVersion    = 0
	keyNonce      = 1
	keyEvent      = 2
	keyVoice      = 3
	keyPresence   = 4
	keyFrames     = 5
	keyWindowMs   = 6
	keyCounter    = 7
	keyConfigHash = 8
	keyInputHash  = 9
	keyPrevDigest = 10
)

// Event classes (mirror he_detector.h).
const (
	EventNone      = 0
	EventVoice     = 1
	EventAlarmTone = 2
)

// Predicate is the decoded, signed detector output.
type Predicate struct {
	Version     uint64
	Nonce       []byte
	EventID     uint64
	VoiceActive bool
	Presence    uint64
	Frames      uint64
	WindowMs    uint64
	Counter     uint64
	ConfigHash  []byte
	InputHash   []byte
	PrevDigest  []byte
}

// EventName returns a human label for the predicate's event class.
func (p *Predicate) EventName() string {
	switch p.EventID {
	case EventAlarmTone:
		return "alarm_tone"
	case EventVoice:
		return "voice"
	default:
		return "none"
	}
}

// Bundle is the on-the-wire bound-output bundle (hex-encoded fields).
type Bundle struct {
	Schema  string `json:"schema"`
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
	PubX    string `json:"pub_x"`
	PubY    string `json:"pub_y"`
}

// VerifyResult is the outcome of verification.
type VerifyResult struct {
	Predicate *Predicate
	OK        bool
	Reason    string
	// NextDigest is SHA-256 of this bundle's payload — the value the NEXT bundle
	// in this device's stream must carry as its prev_digest. Thread it back in as
	// Options.ExpectedPrevDigest to follow an append-only chain (gap detection).
	NextDigest []byte
}

// Options pins what the verifier expects.
type Options struct {
	// ExpectedNonce is the fresh challenge the verifier issued. Required.
	ExpectedNonce []byte
	// PinPubX/PinPubY, if set, must match the bundle's key exactly. This is the
	// device endorsement check: it ties trust to an enrolled device key so an
	// attacker cannot substitute their own (otherwise genuine) TEE. On QEMU/RPi
	// the key is the shared test key, so pinning proves "genuine published
	// code", not device identity — see THREAT_MODEL.md.
	PinPubX, PinPubY []byte
	// LastCounter is the highest counter previously accepted for this device.
	// The bundle's counter must be strictly greater. Use 0 for first contact.
	LastCounter uint64
	// ExpectedPrevDigest, if set, must equal the bundle's prev_digest — i.e. this
	// bundle must chain onto the last one accepted (use the previous result's
	// NextDigest). This makes the stream append-only: a suppressed window breaks
	// the chain. Use 32 zero bytes for the genesis (first) bundle. Leave nil to
	// skip the chain check (single-bundle verification).
	ExpectedPrevDigest []byte
}

var (
	errShortSig  = errors.New("signature must be 64 bytes (r||s)")
	errBadPubKey = errors.New("public key is not on the P-256 curve")
)

// VerifyBundle runs the gates (0: optional pin, 1: signature, 2: freshness,
// 3: anti-replay, 4: optional stream chain) and returns the decoded predicate.
func VerifyBundle(b Bundle, opt Options) VerifyResult {
	payload, err := hex.DecodeString(b.Payload)
	if err != nil {
		return VerifyResult{Reason: "payload hex: " + err.Error()}
	}
	sig, err := hex.DecodeString(b.Sig)
	if err != nil {
		return VerifyResult{Reason: "sig hex: " + err.Error()}
	}
	px, err := hex.DecodeString(b.PubX)
	if err != nil {
		return VerifyResult{Reason: "pub_x hex: " + err.Error()}
	}
	py, err := hex.DecodeString(b.PubY)
	if err != nil {
		return VerifyResult{Reason: "pub_y hex: " + err.Error()}
	}

	// Gate 0: optional endorsement pin (device-identity check).
	if !pinOK(px, py, opt) {
		return VerifyResult{Reason: "public key does not match pinned endorsement"}
	}

	// Gate 1: signature over SHA-256(payload) under the attested key.
	if err := verifySig(payload, sig, px, py); err != nil {
		return VerifyResult{Reason: "signature: " + err.Error()}
	}
	// Gate 1b: the DEVICE signature must be canonical low-s, matching the
	// on-chain OpenZeppelin P256 verifier (which rejects high-s). This makes the
	// host/WASM verifier's acceptance set identical to the chain's even for a
	// MALLEATED sig. (Scoped to the device bundle only — witness/COSE/endorsement
	// cosignatures verified via verifySig are off-chain and not low-s-gated.)
	if !lowS(sig) {
		return VerifyResult{Reason: "signature: non-canonical high-s (must be low-s to match the on-chain verifier)"}
	}

	// Gates 2-4 (+ version/decode) are identical for the raw and COSE envelopes.
	return gatesAfterSig(payload, opt)
}

// pinOK reports whether the bundle's key matches the optional pinned endorsement
// (constant-time). No pin set => always OK.
func pinOK(px, py []byte, opt Options) bool {
	if opt.PinPubX == nil && opt.PinPubY == nil {
		return true
	}
	return subtle.ConstantTimeCompare(px, opt.PinPubX) == 1 &&
		subtle.ConstantTimeCompare(py, opt.PinPubY) == 1
}

// gatesAfterSig runs the envelope-independent checks once the signature over the
// payload has been verified: decode, version, freshness (gate 2), anti-replay
// (gate 3), and the optional stream chain (gate 4). Shared by the raw and
// COSE_Sign1 verification paths so there is exactly one copy of the gate logic.
func gatesAfterSig(payload []byte, opt Options) VerifyResult {
	pred, err := DecodePayload(payload)
	if err != nil {
		return VerifyResult{Reason: "decode: " + err.Error()}
	}
	if pred.Version != PayloadVersion {
		return VerifyResult{Predicate: pred,
			Reason: fmt.Sprintf("unsupported payload version %d", pred.Version)}
	}

	// Gate 2: freshness — signed nonce must equal the issued challenge.
	// An empty (zero-length) expected nonce is treated exactly like a missing
	// one: otherwise it would "match" an empty payload nonce and silently
	// disable freshness (a fail-open). The system never issues an empty nonce.
	if len(opt.ExpectedNonce) == 0 {
		return VerifyResult{Predicate: pred, Reason: "no expected nonce supplied"}
	}
	if len(pred.Nonce) == 0 {
		return VerifyResult{Predicate: pred, Reason: "bundle has no nonce"}
	}
	if subtle.ConstantTimeCompare(pred.Nonce, opt.ExpectedNonce) != 1 {
		return VerifyResult{Predicate: pred,
			Reason: "nonce mismatch (stale/replayed evidence)"}
	}

	// Gate 3: anti-replay — counter must strictly advance.
	if pred.Counter <= opt.LastCounter {
		return VerifyResult{Predicate: pred,
			Reason: fmt.Sprintf("counter %d not greater than last seen %d",
				pred.Counter, opt.LastCounter)}
	}

	// Gate 4 (optional): stream continuity — this bundle must chain onto the last
	// one accepted, so a host can't silently drop a window (the chain breaks).
	if opt.ExpectedPrevDigest != nil {
		if subtle.ConstantTimeCompare(pred.PrevDigest, opt.ExpectedPrevDigest) != 1 {
			return VerifyResult{Predicate: pred,
				Reason: "prev_digest mismatch (a window was suppressed or the chain forked)"}
		}
	}

	next := sha256.Sum256(payload)
	return VerifyResult{Predicate: pred, OK: true, Reason: "verified", NextDigest: next[:]}
}

func verifySig(payload, sig, px, py []byte) error {
	if len(sig) != 64 {
		return errShortSig
	}
	x := new(big.Int).SetBytes(px)
	y := new(big.Int).SetBytes(py)
	if !elliptic.P256().IsOnCurve(x, y) {
		return errBadPubKey
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	h := sha256.Sum256(payload)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, h[:], r, s) {
		return errors.New("ECDSA verify failed")
	}
	return nil
}

// lowS reports whether a 64-byte r||s P-256 signature is canonical low-s
// (s <= N/2). Used to gate the DEVICE signature so the host/WASM verifier's
// acceptance set matches the on-chain OpenZeppelin P256 verifier exactly,
// including for a malleated high-s signature. Honest signers emit low-s (see
// NormalizeLowS, sim/he_bundle.c sign_rs); off-chain cosignatures verified via
// verifySig are intentionally not gated.
func lowS(sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	s := new(big.Int).SetBytes(sig[32:])
	halfN := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	return s.Cmp(halfN) <= 0
}

// NormalizeLowS returns the canonical low-s form of an ECDSA P-256 s value
// (s' = N - s when s > N/2). Signers should emit canonical low-s so a bundle is
// accepted identically by this verifier and the on-chain OpenZeppelin P256
// verifier; ecdsa.Sign returns a random s (high ~half the time).
func NormalizeLowS(s *big.Int) *big.Int {
	halfN := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	if s.Cmp(halfN) > 0 {
		return new(big.Int).Sub(elliptic.P256().Params().N, s)
	}
	return s
}

// ---- minimal CBOR reader for the fixed payload schema ----

type cborReader struct {
	b     []byte
	pos   int
	depth int // current CBOR nesting depth, bounded by maxCBORDepth (anti-DoS)
}

// maxCBORDepth caps recursion in skipValue so a maliciously deep nesting (e.g. a
// long run of CBOR tag bytes) cannot exhaust the stack. Real COSE/EAT/payload
// structures here nest only a handful of levels; 64 is far above any legitimate
// input and far below a stack-exhausting one.
const maxCBORDepth = 64

func (r *cborReader) byte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, errors.New("unexpected end of CBOR")
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

// readHead returns (majorType, argument). It enforces RFC 8949 *deterministic*
// (minimal) integer encoding — the exact inverse of he_payload.c — so a
// non-canonical re-encoding of an otherwise-valid, validly-signed payload is
// rejected rather than silently accepted.
func (r *cborReader) readHead() (byte, uint64, error) {
	ib, err := r.byte()
	if err != nil {
		return 0, 0, err
	}
	major := ib >> 5
	info := ib & 0x1f
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		b, err := r.byte()
		if err != nil {
			return 0, 0, err
		}
		if b < 24 {
			return 0, 0, errors.New("non-minimal CBOR integer (1-byte)")
		}
		return major, uint64(b), nil
	case info == 25:
		v, err := r.readN(2)
		if err != nil {
			return 0, 0, err
		}
		if v <= 0xff {
			return 0, 0, errors.New("non-minimal CBOR integer (2-byte)")
		}
		return major, v, nil
	case info == 26:
		v, err := r.readN(4)
		if err != nil {
			return 0, 0, err
		}
		if v <= 0xffff {
			return 0, 0, errors.New("non-minimal CBOR integer (4-byte)")
		}
		return major, v, nil
	case info == 27:
		v, err := r.readN(8)
		if err != nil {
			return 0, 0, err
		}
		if v <= 0xffffffff {
			return 0, 0, errors.New("non-minimal CBOR integer (8-byte)")
		}
		return major, v, nil
	default:
		return 0, 0, fmt.Errorf("unsupported CBOR additional info %d", info)
	}
}

func (r *cborReader) readN(n int) (uint64, error) {
	var v uint64
	for i := 0; i < n; i++ {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		v = v<<8 | uint64(b)
	}
	return v, nil
}

func (r *cborReader) readUint() (uint64, error) {
	major, v, err := r.readHead()
	if err != nil {
		return 0, err
	}
	if major != 0 {
		return 0, fmt.Errorf("expected uint, got major type %d", major)
	}
	return v, nil
}

func (r *cborReader) readBstr() ([]byte, error) {
	major, n, err := r.readHead()
	if err != nil {
		return nil, err
	}
	if major != 2 {
		return nil, fmt.Errorf("expected bstr, got major type %d", major)
	}
	// Overflow-safe bounds check: never compute r.pos+int(n) (a huge n would
	// overflow to a negative int and slip past the guard, then panic in make).
	if n > uint64(len(r.b)-r.pos) {
		return nil, errors.New("bstr length exceeds buffer")
	}
	out := make([]byte, n)
	copy(out, r.b[r.pos:r.pos+int(n)])
	r.pos += int(n)
	return out, nil
}

func (r *cborReader) readBool() (bool, error) {
	b, err := r.byte()
	if err != nil {
		return false, err
	}
	switch b {
	case 0xf4:
		return false, nil
	case 0xf5:
		return true, nil
	default:
		return false, fmt.Errorf("expected bool, got 0x%02x", b)
	}
}

// DecodePayload parses the fixed bound-output CBOR map into a Predicate.
func DecodePayload(b []byte) (*Predicate, error) {
	r := &cborReader{b: b}
	major, n, err := r.readHead()
	if err != nil {
		return nil, err
	}
	if major != 5 {
		return nil, fmt.Errorf("payload is not a CBOR map (major %d)", major)
	}
	p := &Predicate{}
	const allKeys = (1 << 11) - 1 // keys 0..10 required
	var seen uint
	haveLast := false
	var lastKey uint64
	for i := uint64(0); i < n; i++ {
		key, err := r.readUint()
		if err != nil {
			return nil, fmt.Errorf("map key: %w", err)
		}
		// Deterministic maps require strictly ascending, unique integer keys.
		if haveLast && key <= lastKey {
			return nil, fmt.Errorf("non-canonical map: key %d not after %d",
				key, lastKey)
		}
		lastKey = key
		haveLast = true
		if key < 11 {
			if seen&(1<<key) != 0 {
				return nil, fmt.Errorf("duplicate key %d", key)
			}
			seen |= 1 << key
		}
		switch key {
		case keyVersion:
			p.Version, err = r.readUint()
		case keyNonce:
			p.Nonce, err = r.readBstr()
			if err == nil && len(p.Nonce) > NonceMax {
				return nil, fmt.Errorf("nonce length %d exceeds max %d", len(p.Nonce), NonceMax)
			}
		case keyEvent:
			p.EventID, err = r.readUint()
		case keyVoice:
			p.VoiceActive, err = r.readBool()
		case keyPresence:
			p.Presence, err = r.readUint()
		case keyFrames:
			p.Frames, err = r.readUint()
		case keyWindowMs:
			p.WindowMs, err = r.readUint()
		case keyCounter:
			p.Counter, err = r.readUint()
		case keyConfigHash:
			p.ConfigHash, err = r.readBstr()
			if err == nil && len(p.ConfigHash) != hashLen {
				return nil, fmt.Errorf("config_hash length %d, want %d", len(p.ConfigHash), hashLen)
			}
		case keyInputHash:
			p.InputHash, err = r.readBstr()
			if err == nil && len(p.InputHash) != hashLen {
				return nil, fmt.Errorf("input_hash length %d, want %d", len(p.InputHash), hashLen)
			}
		case keyPrevDigest:
			p.PrevDigest, err = r.readBstr()
			if err == nil && len(p.PrevDigest) != hashLen {
				return nil, fmt.Errorf("prev_digest length %d, want %d", len(p.PrevDigest), hashLen)
			}
		default:
			return nil, fmt.Errorf("unknown payload key %d", key)
		}
		if err != nil {
			return nil, fmt.Errorf("value for key %d: %w", key, err)
		}
	}
	if seen != allKeys {
		return nil, fmt.Errorf("missing required keys (seen mask 0x%x)", seen)
	}
	if r.pos != len(b) {
		return nil, errors.New("trailing bytes after CBOR map")
	}
	return p, nil
}
