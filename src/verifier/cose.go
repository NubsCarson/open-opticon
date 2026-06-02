package verifier

// COSE_Sign1 (RFC 9052) verification for the bound-output envelope — the
// standards-aligned alternative to the raw envelope in bound.go. The signature
// is over the COSE Sig_structure ["Signature1", protected, ext_aad, payload]
// rather than the bare payload; everything after the signature (decode, version,
// freshness, anti-replay, stream chain) is the SAME logic (gatesAfterSig). The
// inner payload is the identical deterministic-CBOR he_payload, so DecodePayload
// and all gates are reused unchanged. Stdlib-only; reuses the cborReader.

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// COSEBundle is the on-the-wire COSE_Sign1 bound-output bundle (hex fields).
type COSEBundle struct {
	Schema string `json:"schema"`
	COSE   string `json:"cose"`
	PubX   string `json:"pub_x"`
	PubY   string `json:"pub_y"`
}

// coseContext is the CBOR encoding of the text string "Signature1" (the
// COSE_Sign1 Sig_structure context), used to rebuild the signed bytes.
var coseContext = []byte{0x6a, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1'}

// VerifyCOSEBundle verifies a COSE_Sign1 bound-output bundle: it checks the
// ES256 signature over the reconstructed Sig_structure under the bundle's key,
// then runs the identical gates as VerifyBundle on the inner payload.
func VerifyCOSEBundle(b COSEBundle, opt Options) VerifyResult {
	cose, err := hex.DecodeString(b.COSE)
	if err != nil {
		return VerifyResult{Reason: "cose hex: " + err.Error()}
	}
	px, err := hex.DecodeString(b.PubX)
	if err != nil {
		return VerifyResult{Reason: "pub_x hex: " + err.Error()}
	}
	py, err := hex.DecodeString(b.PubY)
	if err != nil {
		return VerifyResult{Reason: "pub_y hex: " + err.Error()}
	}

	protBstr, payload, payloadBstr, sig, err := parseCOSESign1(cose)
	if err != nil {
		return VerifyResult{Reason: "cose: " + err.Error()}
	}

	// Gate 0: optional endorsement pin.
	if !pinOK(px, py, opt) {
		return VerifyResult{Reason: "public key does not match pinned endorsement"}
	}

	// Gate 1: signature over SHA-256(Sig_structure) under the attested key.
	if err := verifySig(coseSigStruct(protBstr, payloadBstr), sig, px, py); err != nil {
		return VerifyResult{Reason: "signature: " + err.Error()}
	}

	// Gates 2-4 (+ version/decode) — identical to the raw envelope.
	return gatesAfterSig(payload, opt)
}

// COSEPayload returns the inner payload bytes of a hex-encoded COSE_Sign1 message,
// parsing ONLY — it performs NO cryptographic check. For audit/decode tools (he-dump)
// that inspect what a device committed without verifying; use VerifyCOSEBundle to
// actually verify a COSE bundle.
func COSEPayload(coseHex string) ([]byte, error) {
	raw, err := hex.DecodeString(coseHex)
	if err != nil {
		return nil, err
	}
	_, payload, _, _, err := parseCOSESign1(raw)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// coseSigStruct rebuilds the COSE_Sign1 Sig_structure that was signed:
// [ "Signature1", protected, external_aad(empty), payload ]. The protected and
// payload bstrs are spliced in verbatim (their exact on-wire bytes), so the
// reconstructed bytes match what the signer hashed byte-for-byte.
func coseSigStruct(protBstr, payloadBstr []byte) []byte {
	ss := make([]byte, 0, 1+len(coseContext)+len(protBstr)+1+len(payloadBstr))
	ss = append(ss, 0x84) // array(4)
	ss = append(ss, coseContext...)
	ss = append(ss, protBstr...)
	ss = append(ss, 0x40) // external_aad = empty bstr
	ss = append(ss, payloadBstr...)
	return ss
}

// parseCOSESign1 parses a COSE_Sign1 message and returns the protected header's
// on-wire bstr (head+content), the inner payload bytes, the payload's on-wire
// bstr (head+content), and the 64-byte ES256 signature. It requires the
// protected header to declare alg ES256 (-7). The raw bstr spans are returned so
// the caller can reconstruct the exact Sig_structure that was signed.
func parseCOSESign1(b []byte) (protBstr, payload, payloadBstr, sig []byte, err error) {
	r := &cborReader{b: b}
	// Optional CBOR tag 18 (COSE_Sign1). Accept tagged or untagged.
	if r.pos < len(r.b) && r.b[r.pos] == 0xd2 {
		r.pos++
	}
	major, n, err := r.readHead()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if major != 4 || n != 4 {
		return nil, nil, nil, nil, errors.New("COSE_Sign1 must be a 4-element array")
	}

	// protected: bstr wrapping the CBOR header map; capture its raw on-wire bytes.
	pstart := r.pos
	prot, err := r.readBstr()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("protected: %w", err)
	}
	protBstr = b[pstart:r.pos]
	if err := requireES256(prot); err != nil {
		return nil, nil, nil, nil, err
	}

	// unprotected: a header map — skip it generically (we don't trust it).
	if err := r.skipValue(); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("unprotected: %w", err)
	}

	// payload: bstr; capture raw bytes for the Sig_structure.
	plstart := r.pos
	payload, err = r.readBstr()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("payload: %w", err)
	}
	payloadBstr = b[plstart:r.pos]

	// signature: bstr of exactly 64 bytes (ES256 r||s).
	sig, err = r.readBstr()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("signature: %w", err)
	}
	if len(sig) != 64 {
		return nil, nil, nil, nil, errShortSig
	}
	if r.pos != len(b) {
		return nil, nil, nil, nil, errors.New("trailing bytes after COSE_Sign1")
	}
	return protBstr, payload, payloadBstr, sig, nil
}

// requireES256 checks that the protected-header bstr content is a CBOR map
// declaring alg (label 1) = ES256 (-7). Reusable for any COSE_Sign1 we accept.
func requireES256(protected []byte) error {
	r := &cborReader{b: protected}
	major, n, err := r.readHead()
	if err != nil {
		return fmt.Errorf("protected header: %w", err)
	}
	if major != 5 {
		return errors.New("protected header is not a CBOR map")
	}
	for i := uint64(0); i < n; i++ {
		label, err := r.readUint()
		if err != nil {
			return fmt.Errorf("protected header label: %w", err)
		}
		if label == 1 { // alg
			m, v, err := r.readHead()
			if err != nil {
				return fmt.Errorf("alg value: %w", err)
			}
			// ES256 = -7, CBOR negative int: major type 1, argument 6 (= -1-6).
			if m != 1 || v != 6 {
				return errors.New("COSE alg is not ES256")
			}
			return nil
		}
		if err := r.skipValue(); err != nil { // skip this label's value
			return err
		}
	}
	return errors.New("protected header missing alg (ES256)")
}

// skipValue advances past one complete CBOR data item (any type). Used to skip
// header fields/values we do not interpret. Recursive for arrays/maps/tags.
func (r *cborReader) skipValue() error {
	// Bound recursion: a deeply nested item (array/map/tag) from untrusted input
	// must not exhaust the stack — reject it instead (anti-DoS at the trust boundary).
	if r.depth >= maxCBORDepth {
		return errors.New("CBOR nesting too deep")
	}
	r.depth++
	defer func() { r.depth-- }()
	major, n, err := r.readHead()
	if err != nil {
		return err
	}
	switch major {
	case 0, 1, 7: // uint, negint, simple/float — argument already consumed
		return nil
	case 2, 3: // bstr / tstr — skip n content bytes
		if n > uint64(len(r.b)-r.pos) {
			return errors.New("string length exceeds buffer")
		}
		r.pos += int(n)
		return nil
	case 4: // array — n items
		for i := uint64(0); i < n; i++ {
			if err := r.skipValue(); err != nil {
				return err
			}
		}
		return nil
	case 5: // map — n key/value pairs
		for i := uint64(0); i < n; i++ {
			if err := r.skipValue(); err != nil {
				return err
			}
			if err := r.skipValue(); err != nil {
				return err
			}
		}
		return nil
	case 6: // tag — skip the tagged item
		return r.skipValue()
	default:
		return fmt.Errorf("cannot skip CBOR major type %d", major)
	}
}
