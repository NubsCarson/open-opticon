package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	verifier "honest-ear/verifier"
)

// These exercise the /listen input-validation early-returns, which run before
// any exec of the sim binary — so they need no he-attest-sim present.
func TestListenValidation(t *testing.T) {
	h := listenHandler("/nonexistent-sim")

	cases := []struct {
		name       string
		method     string
		body       []byte
		wantStatus int
		wantReason string // substring expected in the JSON reason (POST cases)
	}{
		{"GET rejected", http.MethodGet, nil, http.StatusMethodNotAllowed, ""},
		{"empty body", http.MethodPost, nil, http.StatusOK, "no audio"},
		{"too short", http.MethodPost, bytes.Repeat([]byte{0}, 32), http.StatusOK, "no audio"},
		{"odd length", http.MethodPost, bytes.Repeat([]byte{1}, 101), http.StatusOK, "16-bit"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "/listen", bytes.NewReader(c.body))
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			if c.wantReason != "" {
				var res result
				if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
					t.Fatalf("bad JSON: %v", err)
				}
				if res.Verified {
					t.Error("verified=true on an invalid request")
				}
				if !strings.Contains(res.Reason, c.wantReason) {
					t.Errorf("reason = %q, want substring %q", res.Reason, c.wantReason)
				}
			}
		})
	}
}

// goldenAlarm is the canonical bound-output payload (nonce AABB, event 2 =
// alarm_tone) — the same vector the verifier package tests use.
func goldenAlarm(t *testing.T) []byte {
	t.Helper()
	const c32 = "1111111111111111111111111111111111111111111111111111111111111111"
	const i32 = "2222222222222222222222222222222222222222222222222222222222222222"
	const p32 = "3333333333333333333333333333333333333333333333333333333333333333"
	b, err := hex.DecodeString("ab" + "0001" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + c32 + "095820" + i32 + "0a5820" + p32)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// mintReq signs payload with a fresh P-256 key and returns the /verify request
// JSON (nonce + the bound-output bundle). The handler pins no key, so a
// self-consistent signature clears the signature + freshness gates.
func mintReq(t *testing.T, payload []byte, nonceHex string) []byte {
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
	s = verifier.NormalizeLowS(s) // canonical low-s, like a real device
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	pad := func(b []byte) []byte { o := make([]byte, 32); copy(o[32-len(b):], b); return o }
	req := verifyReq{Nonce: nonceHex, Bundle: verifier.Bundle{
		Schema:  "honest-ear/bound-output/v1",
		Payload: hex.EncodeToString(payload),
		Sig:     hex.EncodeToString(sig),
		PubX:    hex.EncodeToString(pad(key.PublicKey.X.Bytes())),
		PubY:    hex.EncodeToString(pad(key.PublicKey.Y.Bytes())),
	}}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func postVerify(t *testing.T, body []byte) (int, result) {
	t.Helper()
	rec := httptest.NewRecorder()
	verifyHandler(rec, httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body)))
	var res result
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
	}
	return rec.Code, res
}

func TestVerifyHandler(t *testing.T) {
	// GET is rejected before any parsing.
	rec := httptest.NewRecorder()
	verifyHandler(rec, httptest.NewRequest(http.MethodGet, "/verify", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", rec.Code)
	}

	// Malformed JSON and bad nonce hex fail closed with a clear reason.
	if _, res := postVerify(t, []byte("not json")); res.Verified || !strings.Contains(res.Reason, "bad bundle") {
		t.Errorf("bad JSON: verified=%v reason=%q", res.Verified, res.Reason)
	}
	badNonce := mintReq(t, goldenAlarm(t), "zz")
	if _, res := postVerify(t, badNonce); res.Verified || !strings.Contains(res.Reason, "bad nonce hex") {
		t.Errorf("bad nonce: verified=%v reason=%q", res.Verified, res.Reason)
	}

	// A valid signed bundle whose nonce matches the payload verifies, and
	// fillVerified populates the predicate (success branch, previously untested).
	if _, res := postVerify(t, mintReq(t, goldenAlarm(t), "aabb")); !res.Verified || res.Event != "alarm_tone" {
		t.Errorf("valid bundle: verified=%v event=%q reason=%q", res.Verified, res.Event, res.Reason)
	}

	// Flip one payload byte -> the signature no longer matches -> rejected, and no
	// predicate is shown (the live "tamper test" path).
	p := goldenAlarm(t)
	p[5] ^= 0xff
	if _, res := postVerify(t, mintReqKeepSig(t, p, "aabb")); res.Verified || res.Event != "" {
		t.Errorf("tampered payload accepted: verified=%v event=%q", res.Verified, res.Event)
	}
}

// mintReqKeepSig signs the ORIGINAL golden payload but ships a tampered payload —
// i.e. the signature is over different bytes than presented, so verification must
// fail (mirrors the browser flipping a byte after the device signed).
func mintReqKeepSig(t *testing.T, tamperedPayload []byte, nonceHex string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(goldenAlarm(t)) // sign the GOOD payload
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	s = verifier.NormalizeLowS(s) // canonical low-s, like a real device
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	pad := func(b []byte) []byte { o := make([]byte, 32); copy(o[32-len(b):], b); return o }
	req := verifyReq{Nonce: nonceHex, Bundle: verifier.Bundle{
		Schema:  "honest-ear/bound-output/v1",
		Payload: hex.EncodeToString(tamperedPayload), // ...but present the BAD payload
		Sig:     hex.EncodeToString(sig),
		PubX:    hex.EncodeToString(pad(key.PublicKey.X.Bytes())),
		PubY:    hex.EncodeToString(pad(key.PublicKey.Y.Bytes())),
	}}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// process() is the live "listen" path: it mints a fresh nonce, execs he-attest-sim
// over the PCM, and verifies the returned bound output (the part verifyHandler
// can't cover because it needs the sim). Skips cleanly if the prebuilt sim binary
// is absent (e.g. an offline checkout that didn't `make sim`).
func TestProcessE2E(t *testing.T) {
	sim := filepath.Join("..", "..", "..", "..", "sim", "bin", "he-attest-sim")
	if _, err := os.Stat(sim); err != nil {
		t.Skip("he-attest-sim not built (run `make sim`); skipping the exec path")
	}
	pcm, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "test", "fixtures", "alarm.pcm"))
	if err != nil {
		t.Skipf("alarm fixture missing: %v", err)
	}
	r := process(sim, pcm)
	if !r.Verified || r.Event != "alarm_tone" {
		t.Fatalf("alarm clip: verified=%v event=%q reason=%q", r.Verified, r.Event, r.Reason)
	}
	// The server-minted counter must strictly advance across calls (the atomic
	// counter + LastCounter=ctr-1 anti-replay wiring), and each still verifies.
	r2 := process(sim, pcm)
	if !r2.Verified || r2.Counter <= r.Counter {
		t.Errorf("counter did not advance: %d -> %d (verified=%v)", r.Counter, r2.Counter, r2.Verified)
	}
}
