package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func signReceipt(t *testing.T, r Receipt, key *ecdsa.PrivateKey) ReceiptBundle {
	t.Helper()
	body := ReceiptBody(r)
	sig, err := SignNote(body, key)
	if err != nil {
		t.Fatal(err)
	}
	px, py := PubXY(key)
	return ReceiptBundle{
		Schema: ReceiptOrigin, Body: string(body),
		Sig: hex.EncodeToString(sig), PubX: hex.EncodeToString(px), PubY: hex.EncodeToString(py),
	}
}

func sampleReceipt(prev []byte) Receipt {
	audio := sha256.Sum256([]byte("a 2-second audio window"))
	text := sha256.Sum256([]byte("the transcribed text"))
	return Receipt{
		Origin: ReceiptOrigin, Session: "sess-1", Batch: 1,
		InputHash: audio[:], OutputHash: text[:], Retained: false, PrevDigest: prev,
	}
}

func TestReceiptBodyRoundTrip(t *testing.T) {
	r := sampleReceipt(make([]byte, 32))
	got, err := ParseReceipt(ReceiptBody(r))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Session != r.Session || got.Batch != r.Batch || got.Retained != r.Retained ||
		!bytes.Equal(got.InputHash, r.InputHash) || !bytes.Equal(got.OutputHash, r.OutputHash) ||
		!bytes.Equal(got.PrevDigest, r.PrevDigest) {
		t.Errorf("round trip mismatch: %+v vs %+v", got, r)
	}
}

func TestVerifyReceiptHappyPath(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	px, py := PubXY(key)
	b := signReceipt(t, sampleReceipt(make([]byte, 32)), key)
	res := VerifyReceipt(b, ReceiptOptions{
		ExpectedPrevDigest: make([]byte, 32), // genesis
		PinPubX:            px, PinPubY: py,
		RequireNotRetained: true,
	})
	if !res.OK {
		t.Fatalf("expected OK, got %s", res.Reason)
	}
	if len(res.NextDigest) != 32 {
		t.Errorf("next digest len = %d", len(res.NextDigest))
	}
}

func TestVerifyReceiptRejectsTamper(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := signReceipt(t, sampleReceipt(make([]byte, 32)), key)
	b.Body = b.Body[:10] + "X" + b.Body[11:] // flip a byte after signing
	if VerifyReceipt(b, ReceiptOptions{}).OK {
		t.Error("tampered receipt verified; must fail")
	}
}

func TestVerifyReceiptRejectsWrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := signReceipt(t, sampleReceipt(make([]byte, 32)), key)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ox, oy := PubXY(other)
	b.PubX, b.PubY = hex.EncodeToString(ox), hex.EncodeToString(oy)
	if VerifyReceipt(b, ReceiptOptions{}).OK {
		t.Error("wrong key verified; must fail")
	}
}

func TestVerifyReceiptChainGap(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Receipt with prev = all-zero (genesis), but verifier expects a non-zero prev
	// (i.e. a batch was dropped between what it last saw and this one) -> reject.
	b := signReceipt(t, sampleReceipt(make([]byte, 32)), key)
	res := VerifyReceipt(b, ReceiptOptions{ExpectedPrevDigest: bytes.Repeat([]byte{0x11}, 32)})
	if res.OK {
		t.Error("chain gap accepted; must fail")
	}
}

func TestVerifyReceiptRejectsRetained(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := sampleReceipt(make([]byte, 32))
	r.Retained = true // app admits it kept the raw input
	b := signReceipt(t, r, key)
	if VerifyReceipt(b, ReceiptOptions{RequireNotRetained: true}).OK {
		t.Error("retained-input receipt accepted under RequireNotRetained; must fail")
	}
	// Without the requirement, it verifies (the claim is just surfaced).
	if !VerifyReceipt(b, ReceiptOptions{}).OK {
		t.Error("valid retained receipt should still verify when not required otherwise")
	}
}

// A two-batch session chains: receipt 2's prev_digest == receipt 1's NextDigest.
func TestReceiptChainLinks(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b1 := signReceipt(t, sampleReceipt(make([]byte, 32)), key)
	r1 := VerifyReceipt(b1, ReceiptOptions{ExpectedPrevDigest: make([]byte, 32)})
	if !r1.OK {
		t.Fatalf("batch 1: %s", r1.Reason)
	}
	r2in := sampleReceipt(r1.NextDigest)
	r2in.Batch = 2
	b2 := signReceipt(t, r2in, key)
	r2 := VerifyReceipt(b2, ReceiptOptions{ExpectedPrevDigest: r1.NextDigest})
	if !r2.OK {
		t.Fatalf("batch 2 should chain onto batch 1: %s", r2.Reason)
	}
}
