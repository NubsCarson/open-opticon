package verifier

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestShamirRoundTripAndThreshold(t *testing.T) {
	secret := []byte("a 32-byte symmetric reveal key!!") // 32 bytes
	k, n := 3, 5
	shares, err := ShamirSplit(secret, k, n)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(shares) != n {
		t.Fatalf("got %d shares, want %d", len(shares), n)
	}
	// Any k shares reconstruct exactly; try a few distinct k-subsets.
	for _, idx := range [][]int{{0, 1, 2}, {0, 2, 4}, {1, 3, 4}, {2, 3, 4}} {
		sub := []Share{shares[idx[0]], shares[idx[1]], shares[idx[2]]}
		got, err := ShamirCombine(sub)
		if err != nil {
			t.Fatalf("combine %v: %v", idx, err)
		}
		if !bytes.Equal(leftPadTo(got, len(secret)), secret) {
			t.Errorf("combine %v = %x, want %x", idx, got, secret)
		}
	}
	// k-1 shares must NOT reconstruct the secret (interpolates a different poly).
	got, err := ShamirCombine(shares[:k-1])
	if err != nil {
		t.Fatalf("combine k-1: %v", err)
	}
	if bytes.Equal(leftPadTo(got, len(secret)), secret) {
		t.Error("k-1 shares reconstructed the secret — threshold broken")
	}
}

func TestShamirEdgeValues(t *testing.T) {
	cases := [][]byte{
		{}, // zero secret
		{0x01},
		bigToBytes(new(big.Int).Sub(shamirPrime, big.NewInt(1))), // p-1, the max
	}
	for ci, secret := range cases {
		shares, err := ShamirSplit(secret, 2, 3)
		if err != nil {
			t.Fatalf("case %d split: %v", ci, err)
		}
		got, err := ShamirCombine(shares[:2])
		if err != nil {
			t.Fatalf("case %d combine: %v", ci, err)
		}
		want := new(big.Int).SetBytes(secret)
		if new(big.Int).SetBytes(got).Cmp(want) != 0 {
			t.Errorf("case %d: got %x want %x", ci, got, secret)
		}
	}
	// A secret >= prime must be rejected.
	if _, err := ShamirSplit(bigToBytes(shamirPrime), 2, 3); err == nil {
		t.Error("expected rejection of secret >= field prime")
	}
}

func TestShamirRandomFuzz(t *testing.T) {
	for i := 0; i < 200; i++ {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		shares, err := ShamirSplit(secret, 3, 6)
		if err != nil {
			t.Fatalf("split: %v", err)
		}
		got, err := ShamirCombine([]Share{shares[5], shares[1], shares[3]})
		if err != nil {
			t.Fatalf("combine: %v", err)
		}
		if !bytes.Equal(leftPadTo(got, 32), secret) {
			t.Fatalf("iter %d: mismatch", i)
		}
	}
}

func TestShamirRejectsBadInput(t *testing.T) {
	s, _ := ShamirSplit([]byte("x"), 2, 3)
	if _, err := ShamirSplit([]byte("x"), 1, 3); err == nil {
		t.Error("k<2 should error")
	}
	if _, err := ShamirSplit([]byte("x"), 4, 3); err == nil {
		t.Error("n<k should error")
	}
	// duplicate X must be rejected.
	if _, err := ShamirCombine([]Share{s[0], s[0]}); err == nil {
		t.Error("duplicate X should error")
	}
}

func TestSealOpenAndTamper(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	pt := []byte("the full predicate stream that only a quorum may reveal")
	ct, err := SealStream(pt, key)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenStream(ct, key)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open round-trip failed: %v", err)
	}
	// A flipped ciphertext byte must fail authentication.
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 0xff
	if _, err := OpenStream(bad, key); err == nil {
		t.Error("tampered ciphertext opened — GCM auth not enforced")
	}
	// A wrong key must fail.
	wrong := make([]byte, 32)
	wrong[0] = key[0] ^ 0x01
	copy(wrong[1:], key[1:])
	if _, err := OpenStream(ct, wrong); err == nil {
		t.Error("wrong key opened the ciphertext")
	}
}

func TestThresholdSealRevealK(t *testing.T) {
	pt := []byte("full record: window-by-window predicate stream + raw refs")
	k, n := 3, 5
	sr, err := ThresholdSeal(pt, k, n)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// k shares reveal exactly.
	got, err := ThresholdOpen(sr, sr.Shares[:k])
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("k-share open failed: %v", err)
	}
	// k-1 shares are refused outright.
	if _, err := ThresholdOpen(sr, sr.Shares[:k-1]); err == nil {
		t.Error("k-1 shares opened the sealed record")
	}
	// Even bypassing the count guard, a wrong reconstructed key fails GCM.
	wrongKey, _ := ShamirCombine(sr.Shares[:k-1])
	key := leftPadTo(wrongKey, 32)
	if _, err := OpenStream(sr.Ciphertext, key); err == nil {
		t.Error("k-1 reconstructed key opened the ciphertext")
	}
}

// Consent-gated query: disclose ONE window of a logged predicate stream and prove
// it belongs to the signed stream, without revealing the other windows.
func TestWindowDisclosure(t *testing.T) {
	var log MerkleLog
	windows := [][]byte{
		[]byte("w0: presence=0 event=none"),
		[]byte("w1: presence=1 event=alarm_tone"),
		[]byte("w2: presence=1 event=voice"),
		[]byte("w3: presence=0 event=none"),
	}
	for _, w := range windows {
		log.Add(w)
	}
	root := log.Root()

	d, err := log.DiscloseWindow(1)
	if err != nil {
		t.Fatalf("disclose: %v", err)
	}
	if !VerifyWindowDisclosure(d, root) {
		t.Fatal("honest single-window disclosure did not verify")
	}
	if !bytes.Equal(d.Entry, windows[1]) {
		t.Errorf("disclosed wrong entry: %q", d.Entry)
	}
	// A tampered entry must fail under the same root.
	bad := &WindowDisclosure{Index: d.Index, Size: d.Size, Entry: []byte("w1: presence=0 event=none"), Proof: d.Proof}
	if VerifyWindowDisclosure(bad, root) {
		t.Error("tampered window entry verified — selective disclosure is forgeable")
	}
	// A tampered proof must fail.
	if len(d.Proof) > 0 {
		badProof := &WindowDisclosure{Index: d.Index, Size: d.Size, Entry: d.Entry, Proof: append([][32]byte(nil), d.Proof...)}
		badProof.Proof[0][0] ^= 0xff
		if VerifyWindowDisclosure(badProof, root) {
			t.Error("tampered inclusion proof verified")
		}
	}
}

// leftPadTo left-pads b with zero bytes to length n (n >= len(b)).
func leftPadTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func bigToBytes(x *big.Int) []byte { return x.Bytes() }
