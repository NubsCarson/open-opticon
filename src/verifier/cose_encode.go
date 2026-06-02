package verifier

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

// COSE_Sign1 encoder — the production counterpart to the verify side in cose.go.
// One signing path (ECDSA-P256 / ES256, 64-byte r||s) and one Sig_structure
// builder (coseSigStruct) shared with verification, so what we emit is exactly
// what parseCOSESign1 + VerifyCOSEBundle accept.

// coseProtected is the COSE protected-header bstr: {1: -7} = alg ES256.
var coseProtected = []byte{0x43, 0xa1, 0x01, 0x26}

// bstrHead returns the CBOR byte-string head for length n (smallest form). COSE
// payloads here are well under 64KiB, so the 2- and 3-byte forms suffice.
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

// SignCOSESign1 wraps payload in a tagged (CBOR tag 18) COSE_Sign1 with alg
// ES256: it signs SHA-256 of the COSE Sig_structure (built via the same
// coseSigStruct verification uses) with key, and emits the on-wire message
// (protected ‖ {} ‖ payload ‖ 64-byte r||s). Verify with VerifyCOSEBundle.
func SignCOSESign1(payload []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	payloadBstr := append(bstrHead(len(payload)), payload...)
	h := sha256.Sum256(coseSigStruct(coseProtected, payloadBstr))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	msg := []byte{0xd2, 0x84} // tag(18), array(4)
	msg = append(msg, coseProtected...)
	msg = append(msg, 0xa0) // unprotected {}
	msg = append(msg, payloadBstr...)
	msg = append(msg, bstrHead(64)...)
	msg = append(msg, sig...)
	return msg, nil
}
