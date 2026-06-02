package main

import (
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
	"sync"
	"testing"
	"time"

	verifier "honest-ear/verifier"
)

func newServer() *server {
	return &server{sessions: map[string]*session{}, baseURL: "http://x", ttl: time.Minute}
}

func TestStatusLifecycle(t *testing.T) {
	s := newServer()
	s.sessions["sid1"] = &session{nonce: []byte{1}, createdAt: time.Now()}

	get := func(sid string) map[string]string {
		rr := httptest.NewRecorder()
		s.handleStatus(rr, httptest.NewRequest(http.MethodGet, "/status?session="+sid, nil))
		var m map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatalf("status json: %v", err)
		}
		return m
	}

	if m := get("nope"); m["state"] != "unknown" {
		t.Errorf("unknown session state = %q", m["state"])
	}
	if m := get("sid1"); m["state"] != "pending" {
		t.Errorf("fresh session state = %q, want pending", m["state"])
	}
	// simulate an attest having recorded a verdict
	s.sessions["sid1"].verdict = "PASS"
	s.sessions["sid1"].event = "alarm_tone"
	m := get("sid1")
	if m["state"] != "done" || m["verdict"] != "PASS" || m["event"] != "alarm_tone" {
		t.Errorf("done status = %+v", m)
	}
}

func TestVerifyPageServesHTML(t *testing.T) {
	s := newServer()
	rr := httptest.NewRecorder()
	s.handleVerifyPage(rr, httptest.NewRequest(http.MethodGet, "/v?session=abc123", nil))
	body := rr.Body.String()
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(body, "live verification") || !strings.Contains(body, "abc123") {
		t.Errorf("verify page missing expected content")
	}
}

// goldenNonce is the nonce embedded in goldenPayload (key 1 = 0xAABB).
var goldenNonce = []byte{0xaa, 0xbb}

// goldenPayload is the exact deterministic-CBOR bound-output payload from
// test_payload.c (mirrors bound_test.go's golden): {version:1, nonce:AABB,
// event:2 (alarm_tone), voice:false, presence:1, frames:10, window_ms:160,
// counter:7, config/input/prev = 0x11/0x22/0x33 * 32}.
func goldenPayload(t *testing.T) []byte {
	t.Helper()
	const c32 = "1111111111111111111111111111111111111111111111111111111111111111"
	const i32 = "2222222222222222222222222222222222222222222222222222222222222222"
	const p32 = "3333333333333333333333333333333333333333333333333333333333333333"
	b, err := hex.DecodeString("ab" + "0001" + "0142aabb" + "0202" + "03f4" + "0401" +
		"050a" + "0618a0" + "0707" + "085820" + c32 + "095820" + i32 + "0a5820" + p32)
	if err != nil {
		t.Fatalf("golden payload: %v", err)
	}
	return b
}

// signBundle signs SHA-256(payload) with a fresh P-256 key. The test server pins
// no key, so a self-consistent signature clears the sig + freshness gates.
func signBundle(t *testing.T, payload []byte) verifier.Bundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	pad := func(b []byte) []byte { out := make([]byte, 32); copy(out[32-len(b):], b); return out }
	return verifier.Bundle{
		Schema:  "honest-ear/bound-output/v1",
		Payload: hex.EncodeToString(payload),
		Sig:     hex.EncodeToString(sig),
		PubX:    hex.EncodeToString(pad(key.PublicKey.X.Bytes())),
		PubY:    hex.EncodeToString(pad(key.PublicKey.Y.Bytes())),
	}
}

func TestChallengeMintsFreshSession(t *testing.T) {
	s := newServer()
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, httptest.NewRequest(http.MethodGet, "/challenge", nil))
	if rr.Code != 200 {
		t.Fatalf("challenge code = %d, want 200", rr.Code)
	}
	var m map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("challenge json: %v", err)
	}
	if len(m["nonce"]) != 64 { // 32 bytes, hex-encoded
		t.Errorf("nonce hex len = %d, want 64", len(m["nonce"]))
	}
	if m["session"] == "" || s.sessions[m["session"]] == nil {
		t.Errorf("session not created: %+v", m)
	}
}

// The unauthenticated /challenge flood guard: at maxSessions the server must shed
// load with 503 rather than grow memory without bound.
func TestChallengeFloodCapReturns503(t *testing.T) {
	s := newServer()
	now := time.Now()
	for i := 0; i < maxSessions; i++ {
		s.sessions[randHex(8)] = &session{nonce: []byte{1}, createdAt: now}
	}
	rr := httptest.NewRecorder()
	s.handleChallenge(rr, httptest.NewRequest(http.MethodGet, "/challenge", nil))
	if rr.Code != 503 {
		t.Fatalf("flood: code = %d, want 503", rr.Code)
	}
}

func TestGCEvictsExpiredSessions(t *testing.T) {
	s := newServer() // ttl = 1 minute
	s.sessions["old"] = &session{nonce: []byte{1}, createdAt: time.Now().Add(-2 * time.Minute)}
	s.sessions["fresh"] = &session{nonce: []byte{1}, createdAt: time.Now()}
	s.mu.Lock()
	s.gcLocked()
	s.mu.Unlock()
	if _, ok := s.sessions["old"]; ok {
		t.Error("expired session not evicted by gcLocked")
	}
	if _, ok := s.sessions["fresh"]; !ok {
		t.Error("fresh session wrongly evicted")
	}
}

func TestAttestUnknownSessionFails(t *testing.T) {
	s := newServer()
	rr := httptest.NewRecorder()
	s.handleAttest(rr, httptest.NewRequest(http.MethodPost, "/attest?session=nope", strings.NewReader("{}")))
	if rr.Code != 404 {
		t.Fatalf("unknown session code = %d, want 404", rr.Code)
	}
	var m map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["verdict"] != "FAIL" {
		t.Errorf("verdict = %q, want FAIL", m["verdict"])
	}
}

func TestAttestBadBundleFails(t *testing.T) {
	s := newServer()
	s.sessions["sid"] = &session{nonce: goldenNonce, createdAt: time.Now()}
	rr := httptest.NewRecorder()
	s.handleAttest(rr, httptest.NewRequest(http.MethodPost, "/attest?session=sid", strings.NewReader("not json")))
	if rr.Code != 400 {
		t.Fatalf("bad bundle code = %d, want 400", rr.Code)
	}
}

// The anti-replay compare-and-advance: several concurrent attests carrying the
// same counter for one session must yield exactly ONE PASS and the rest replay
// FAILs — the in-memory analogue of the on-chain counter gate. Also exercises the
// per-session lock under `go test -race`.
func TestVerifyAndRecordConcurrentReplay(t *testing.T) {
	s := newServer()
	sess := &session{nonce: goldenNonce, createdAt: time.Now()} // lastCounter 0; golden counter is 7
	s.sessions["sid"] = sess

	const n = 8
	payload := goldenPayload(t)
	bundles := make([]verifier.Bundle, n)
	for i := range bundles {
		bundles[i] = signBundle(t, payload) // distinct keys, all counter 7
	}

	var wg sync.WaitGroup
	verdicts := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out := s.verifyAndRecord("sid", sess, bundles[i])
			verdicts[i], _ = out["verdict"].(string)
		}(i)
	}
	wg.Wait()

	pass := 0
	for _, v := range verdicts {
		if v == "PASS" {
			pass++
		}
	}
	if pass != 1 {
		t.Errorf("concurrent attests admitted %d PASS, want exactly 1 (anti-replay)", pass)
	}
	if sess.lastCounter != 7 {
		t.Errorf("lastCounter = %d, want 7 (the one admitted counter)", sess.lastCounter)
	}
}

// On a PASS, /status must carry the proofView so the walk-up page can answer the
// program's 5 questions with the real verified artifacts (predicate + bundle).
func TestStatusReturnsProofOnPass(t *testing.T) {
	s := newServer()
	sess := &session{nonce: goldenNonce, createdAt: time.Now()}
	s.sessions["sid"] = sess
	if out := s.verifyAndRecord("sid", sess, signBundle(t, goldenPayload(t))); out["verdict"] != "PASS" {
		t.Fatalf("verdict = %v, want PASS", out["verdict"])
	}
	rr := httptest.NewRecorder()
	s.handleStatus(rr, httptest.NewRequest(http.MethodGet, "/status?session=sid", nil))
	var resp statusResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("status json: %v", err)
	}
	if resp.State != "done" || resp.Verdict != "PASS" {
		t.Fatalf("status = %+v", resp)
	}
	if resp.Proof == nil {
		t.Fatal("proof missing on PASS")
	}
	if resp.Proof.Event != "alarm_tone" {
		t.Errorf("proof.event = %q, want alarm_tone", resp.Proof.Event)
	}
	// golden payload binds config_hash 0x11*32 and input_hash 0x22*32.
	if resp.Proof.ConfigHash == "" || resp.Proof.InputHash == "" {
		t.Error("proof missing config_hash/input_hash")
	}
	if resp.Proof.Payload == "" || resp.Proof.Sig == "" || resp.Proof.PubX == "" {
		t.Error("proof missing the signed bundle artifact")
	}
	if resp.Proof.Pinned {
		t.Error("pinned should be false when the server set no endorsement pin")
	}
}

// A pending session must NOT leak a proof, and unknown sessions stay unknown.
func TestStatusNoProofBeforePass(t *testing.T) {
	s := newServer()
	s.sessions["sid"] = &session{nonce: goldenNonce, createdAt: time.Now()}
	rr := httptest.NewRecorder()
	s.handleStatus(rr, httptest.NewRequest(http.MethodGet, "/status?session=sid", nil))
	var resp statusResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("status json: %v", err)
	}
	if resp.State != "pending" || resp.Proof != nil {
		t.Errorf("pending status leaked proof or wrong state: %+v", resp)
	}
}

// The walk-up page must answer all 5 program questions and must NOT reintroduce
// the old overclaim (the bare signature does not prove "no audio left the device"
// — that is a firmware/attestation-tier claim, shown as such in the proof panel).
func TestVerifyPageAnswersFiveQuestionsNoOverclaim(t *testing.T) {
	s := newServer()
	rr := httptest.NewRecorder()
	s.handleVerifyPage(rr, httptest.NewRequest(http.MethodGet, "/v?session=abc", nil))
	body := rr.Body.String()
	for _, q := range []string{
		"what gets captured", "where does it go", "who can access",
		"how long is it kept", "how is it used", "show me the proof",
	} {
		if !strings.Contains(body, q) {
			t.Errorf("walk-up page missing question/affordance: %q", q)
		}
	}
	if strings.Contains(body, "No audio left the device") {
		t.Error("page reintroduced the 'No audio left the device' overclaim")
	}
}

// A PASS sets the proof; a later replay FAIL on the same session must CLEAR it,
// so /status never shows a stale PASS proof next to a FAIL verdict.
func TestProofClearedOnLaterFail(t *testing.T) {
	s := newServer()
	sess := &session{nonce: goldenNonce, createdAt: time.Now()}
	s.sessions["sid"] = sess
	payload := goldenPayload(t)
	if out := s.verifyAndRecord("sid", sess, signBundle(t, payload)); out["verdict"] != "PASS" {
		t.Fatalf("first attest = %v, want PASS", out["verdict"])
	}
	if sess.proof == nil {
		t.Fatal("proof not set after PASS")
	}
	// Re-submit the same counter (7) — must FAIL as a replay and clear the proof.
	if out := s.verifyAndRecord("sid", sess, signBundle(t, payload)); out["verdict"] != "FAIL" {
		t.Fatalf("replay attest = %v, want FAIL", out["verdict"])
	}
	if sess.proof != nil {
		t.Error("stale proof left attached after a replay FAIL")
	}
}

// The --sim "simulate a device" walk-up loop (handleSimulate): the homepage button
// and the load-bearing way the /v flow reaches a real verdict in a browser with no
// separate device. It signs THIS session's nonce via the host sim, computes the
// next counter under the lock, and runs the same verify+record path. Hermetic:
// skips cleanly if the prebuilt sim is absent (an offline checkout that didn't
// `make sim`); no hardware, r0vm, or network.
func TestSimulateWalkUpLoop(t *testing.T) {
	sim := filepath.Join("..", "..", "..", "..", "sim", "bin", "he-attest-sim")
	if _, err := os.Stat(sim); err != nil {
		t.Skip("he-attest-sim not built (run `make sim`); skipping the --sim exec path")
	}
	clip, err := writeAlarmClip()
	if err != nil {
		t.Fatalf("writeAlarmClip: %v", err)
	}
	defer os.Remove(clip)

	s := newServer()
	s.simPath, s.clipPath = sim, clip
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	s.sessions["sid"] = &session{nonce: nonce, createdAt: time.Now()}

	simulate := func() map[string]any {
		rr := httptest.NewRecorder()
		s.handleSimulate(rr, httptest.NewRequest(http.MethodGet, "/simulate?session=sid", nil))
		if rr.Code != 200 {
			t.Fatalf("simulate code = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatalf("simulate json: %v", err)
		}
		return m
	}

	// First simulate: the sim signs this session's nonce, the alarm clip classifies
	// as alarm_tone, and the bundle verifies through the same gates as a real device.
	m1 := simulate()
	if m1["verdict"] != "PASS" || m1["event"] != "alarm_tone" {
		t.Fatalf("first simulate = %+v, want PASS / alarm_tone", m1)
	}
	c1 := s.sessions["sid"].lastCounter
	if c1 == 0 {
		t.Error("counter did not advance after the first simulate (lastCounter+1 wiring)")
	}

	// Second simulate on the SAME session: ctr = lastCounter+1, must still PASS and
	// the counter must strictly advance — the anti-replay gate through the sim path.
	if m2 := simulate(); m2["verdict"] != "PASS" {
		t.Fatalf("second simulate = %+v, want PASS", m2)
	}
	if c2 := s.sessions["sid"].lastCounter; c2 <= c1 {
		t.Errorf("counter did not strictly advance across simulates: %d -> %d", c1, c2)
	}
}

// handleSimulate must fail closed (500 + FAIL, not panic, not a false PASS) when the
// sim binary can't be run — covers the exec-error branch hermetically (no sim needed).
func TestSimulateExecFailureFailsClosed(t *testing.T) {
	s := newServer()
	s.simPath, s.clipPath = "/nonexistent/he-attest-sim", "/nonexistent.pcm"
	s.sessions["sid"] = &session{nonce: []byte{1, 2, 3}, createdAt: time.Now()}
	rr := httptest.NewRecorder()
	s.handleSimulate(rr, httptest.NewRequest(http.MethodGet, "/simulate?session=sid", nil))
	if rr.Code != 500 {
		t.Fatalf("missing-sim code = %d, want 500", rr.Code)
	}
	var m map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["verdict"] != "FAIL" || !strings.Contains(m["reason"], "simulator failed") {
		t.Errorf("exec failure = %+v, want FAIL / 'simulator failed'", m)
	}
}
