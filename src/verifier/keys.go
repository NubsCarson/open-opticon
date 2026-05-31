package verifier

// Small shared helpers for the transparency-log tooling (log operator + witnesses)
// so the P-256 key parsing lives in exactly one place.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"math/big"
)

// PrivKeyFromHex parses a 32-byte P-256 private scalar (hex, as `he-log genkey`
// prints) into an *ecdsa.PrivateKey with the public point derived.
func PrivKeyFromHex(h string) (*ecdsa.PrivateKey, error) {
	d, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	if len(d) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}
	k := new(ecdsa.PrivateKey)
	k.Curve = elliptic.P256()
	k.D = new(big.Int).SetBytes(d)
	k.PublicKey.X, k.PublicKey.Y = elliptic.P256().ScalarBaseMult(d)
	return k, nil
}

// PubXY returns the 32-byte big-endian X and Y coordinates of a P-256 key.
func PubXY(k *ecdsa.PrivateKey) (x, y []byte) {
	return leftPad32(k.PublicKey.X.Bytes()), leftPad32(k.PublicKey.Y.Bytes())
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
