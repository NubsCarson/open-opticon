// Threshold reveal + consent-gated disclosure (credible-sensors Track 6 mechanisms).
//
// Track 6 ("consent, query, policy") asks: a recording's full record should be
// revealable only with group agreement, and a verifier should be able to learn a
// single fact without seeing everything else. This file provides two host-side,
// stdlib-only MECHANISMS for that:
//
//  1. Threshold reveal — a sealed artifact (e.g. a full predicate stream) is
//     encrypted under a random key; that key is split into n shares via Shamir
//     secret sharing so any k of n holders can reconstruct it, while k-1 learn
//     nothing — the construction is information-theoretic (uniform coefficients
//     over the field), demonstrated in TestShamirInformationTheoretic. Group
//     agreement, enforced by math.
//
//  2. Consent-gated disclosure — one window of a logged predicate stream is
//     revealed with a Merkle inclusion proof, so a verifier confirms that exact
//     window belongs to the signed stream WITHOUT seeing the other windows.
//
// HONEST SCOPE: these are mechanisms, not a solution to the joint-data problem
// (one recording, many people, conflicting wishes) — that remains open. Share
// custody and key lifecycle are operational policy, not enforced here. Tier-1
// (host, stdlib): same trust tier as receipt.go / transparency.go.
package verifier

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// shamirPrime is the Mersenne prime M521 = 2^521 - 1. Secrets are field elements
// strictly below it; a 32-byte symmetric key (< 2^256) fits with wide margin, so
// arbitrary artifacts are sealed under such a key and only the key is split.
var shamirPrime = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 521)
	return p.Sub(p, big.NewInt(1))
}()

// Share is one point (X, Y) on the secret-sharing polynomial; X is in 1..n and Y
// is a big-endian field element. Distinct X values are required to combine.
type Share struct {
	X int
	Y []byte
}

// ShamirSplit splits secret into n shares such that any k reconstruct it and any
// k-1 reveal nothing. secret is interpreted as a big-endian field element and
// must be < 2^521-1 (so up to 65 bytes; a 32-byte key fits easily).
func ShamirSplit(secret []byte, k, n int) ([]Share, error) {
	if k < 2 || n < k || n > 255 {
		return nil, errors.New("shamir: need 2 <= k <= n <= 255")
	}
	s := new(big.Int).SetBytes(secret)
	if s.Cmp(shamirPrime) >= 0 {
		return nil, errors.New("shamir: secret too large for the field (must be < 2^521-1)")
	}
	// Polynomial coefficients: coeffs[0] = secret, coeffs[1..k-1] random in [0,p).
	coeffs := make([]*big.Int, k)
	coeffs[0] = s
	for i := 1; i < k; i++ {
		c, err := rand.Int(rand.Reader, shamirPrime)
		if err != nil {
			return nil, err
		}
		coeffs[i] = c
	}
	shares := make([]Share, n)
	for idx := 1; idx <= n; idx++ {
		x := big.NewInt(int64(idx))
		// Horner evaluation of the polynomial at x, mod p.
		y := new(big.Int).Set(coeffs[k-1])
		for i := k - 2; i >= 0; i-- {
			y.Mul(y, x)
			y.Add(y, coeffs[i])
			y.Mod(y, shamirPrime)
		}
		shares[idx-1] = Share{X: idx, Y: y.Bytes()}
	}
	return shares, nil
}

// ShamirCombine reconstructs the secret from the shares via Lagrange
// interpolation at x=0. Returns the minimal big-endian encoding (the caller
// left-pads to a known length if needed).
//
// It does NOT know the threshold k: with exactly the right k shares it returns
// the secret; with fewer it interpolates a lower-degree polynomial and returns a
// value unrelated to the secret. Enforcing the count is the caller's job
// (ThresholdOpen does it); k-1 shares are information-theoretically consistent
// with every candidate secret (see TestShamirInformationTheoretic).
func ShamirCombine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("shamir: need at least 2 shares")
	}
	seen := make(map[int]bool, len(shares))
	for _, sh := range shares {
		if sh.X <= 0 {
			return nil, errors.New("shamir: share X must be >= 1")
		}
		if seen[sh.X] {
			return nil, errors.New("shamir: duplicate share X")
		}
		seen[sh.X] = true
	}
	secret := new(big.Int)
	for j := range shares {
		xj := big.NewInt(int64(shares[j].X))
		yj := new(big.Int).SetBytes(shares[j].Y)
		num := big.NewInt(1) // product of (0 - x_m) = -x_m
		den := big.NewInt(1) // product of (x_j - x_m)
		for m := range shares {
			if m == j {
				continue
			}
			xm := big.NewInt(int64(shares[m].X))
			num.Mul(num, new(big.Int).Neg(xm))
			num.Mod(num, shamirPrime)
			den.Mul(den, new(big.Int).Sub(xj, xm))
			den.Mod(den, shamirPrime)
		}
		denInv := new(big.Int).ModInverse(den, shamirPrime)
		if denInv == nil {
			return nil, errors.New("shamir: non-invertible denominator (duplicate X?)")
		}
		term := new(big.Int).Mul(yj, num)
		term.Mod(term, shamirPrime)
		term.Mul(term, denInv)
		term.Mod(term, shamirPrime)
		secret.Add(secret, term)
		secret.Mod(secret, shamirPrime)
	}
	return secret.Bytes(), nil
}

// SealStream encrypts plaintext under a 16/24/32-byte key with AES-GCM
// (authenticated). The random nonce is prepended to the returned ciphertext.
func SealStream(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// OpenStream reverses SealStream; it fails (GCM auth) on any tamper or wrong key.
func OpenStream(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext shorter than nonce")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// SealedReveal is an artifact sealed for k-of-n threshold reveal: the ciphertext
// plus the shares of its AES-256 key. Distribute one share per holder; any k
// reconstruct the key and open it.
type SealedReveal struct {
	Ciphertext []byte
	Shares     []Share
	K, N       int
}

// ThresholdSeal encrypts plaintext under a fresh AES-256 key and splits that key
// into n shares with a k-of-n threshold.
func ThresholdSeal(plaintext []byte, k, n int) (*SealedReveal, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	ct, err := SealStream(plaintext, key)
	if err != nil {
		return nil, err
	}
	shares, err := ShamirSplit(key, k, n)
	if err != nil {
		return nil, err
	}
	return &SealedReveal{Ciphertext: ct, Shares: shares, K: k, N: n}, nil
}

// ThresholdOpen reconstructs the key from >= K shares and opens the ciphertext.
// With fewer than K shares it refuses; even if that guard were bypassed, the
// reconstructed key would be wrong and GCM authentication would reject it.
func ThresholdOpen(sr *SealedReveal, shares []Share) ([]byte, error) {
	if len(shares) < sr.K {
		return nil, fmt.Errorf("threshold: need %d shares, got %d", sr.K, len(shares))
	}
	keyBytes, err := ShamirCombine(shares)
	if err != nil {
		return nil, err
	}
	if len(keyBytes) > 32 {
		return nil, errors.New("threshold: reconstructed key larger than 32 bytes")
	}
	key := make([]byte, 32) // left-pad: ShamirCombine drops leading zero bytes
	copy(key[32-len(keyBytes):], keyBytes)
	return OpenStream(sr.Ciphertext, key)
}

// WindowDisclosure is a consent-gated single-window reveal: it discloses ONE
// window's predicate entry and a Merkle inclusion proof, so a verifier confirms
// that exact window belongs to the logged stream without seeing any other window.
type WindowDisclosure struct {
	Index int
	Size  int
	Entry []byte
	Proof [][32]byte
}

// DiscloseWindow builds a single-window disclosure for the given log index.
func (l *MerkleLog) DiscloseWindow(index int) (*WindowDisclosure, error) {
	proof, err := l.InclusionProof(index)
	if err != nil {
		return nil, err
	}
	entry := append([]byte(nil), l.Leaves[index]...)
	return &WindowDisclosure{Index: index, Size: len(l.Leaves), Entry: entry, Proof: proof}, nil
}

// VerifyWindowDisclosure checks the disclosed window belongs to the stream whose
// Merkle root is root (e.g. a root carried by a signed checkpoint). It learns
// only that one window; the others stay hidden behind the tree.
func VerifyWindowDisclosure(d *WindowDisclosure, root [32]byte) bool {
	if d == nil {
		return false
	}
	return VerifyInclusion(d.Entry, d.Index, d.Size, d.Proof, root)
}
