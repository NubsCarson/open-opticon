// Package verifier checks Honest Ear "bound-output" bundles.
//
// A bundle ties the detector's minimal output to the same P-256 key whose
// identity is proven by OP-TEE remote attestation. Verification is three
// independent gates, ALL of which must pass:
//
//  1. Signature: ECDSA-P256 over SHA-256(payload) verifies under the attested
//     public key. (Proves the bytes were produced by the attested enclave key
//     and were not altered by the untrusted host.)
//  2. Freshness: the nonce inside the signed payload equals the fresh nonce
//     the verifier just issued. (Defeats replay / the static-QR swap.)
//  3. Anti-replay: the monotonic counter strictly exceeds the last one seen
//     for this device. (Defeats re-presentation of an old, otherwise-valid
//     bundle within a session.)
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
}

var (
	errShortSig  = errors.New("signature must be 64 bytes (r||s)")
	errBadPubKey = errors.New("public key is not on the P-256 curve")
)

// VerifyBundle runs all three gates and returns the decoded predicate.
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
	if opt.PinPubX != nil || opt.PinPubY != nil {
		if subtle.ConstantTimeCompare(px, opt.PinPubX) != 1 ||
			subtle.ConstantTimeCompare(py, opt.PinPubY) != 1 {
			return VerifyResult{Reason: "public key does not match pinned endorsement"}
		}
	}

	// Gate 1: signature over SHA-256(payload) under the attested key.
	if err := verifySig(payload, sig, px, py); err != nil {
		return VerifyResult{Reason: "signature: " + err.Error()}
	}

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

	return VerifyResult{Predicate: pred, OK: true, Reason: "verified"}
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

// ---- minimal CBOR reader for the fixed payload schema ----

type cborReader struct {
	b   []byte
	pos int
}

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
	const allKeys = (1 << 10) - 1 // keys 0..9 required
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
		if key < 10 {
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
		case keyInputHash:
			p.InputHash, err = r.readBstr()
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
