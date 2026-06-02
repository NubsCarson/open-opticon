package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	verifier "honest-ear/verifier"
)

func TestStateFileRoundTripAndCorruption(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	root := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	st := &witnessState{Origin: "honest-ear.log/v1", Size: 3, Root: root}
	if err := saveState(p, st); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadState(p)
	if err != nil || *got != *st {
		t.Fatalf("round trip: %+v err=%v", got, err)
	}

	// Missing file -> empty baseline, no error (honest first run).
	got, err = loadState(filepath.Join(dir, "absent.json"))
	if err != nil || got.Root != "" {
		t.Errorf("missing file should baseline cleanly, got %+v err=%v", got, err)
	}

	// Present-but-corrupt JSON -> error (must NOT silently reset to baseline).
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(p); err == nil {
		t.Error("corrupt state file accepted; must error")
	}

	// Present with a malformed root -> error.
	if err := os.WriteFile(p, []byte(`{"origin":"o","size":1,"root":"zz"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(p); err == nil {
		t.Error("invalid root in state accepted; must error")
	}
}

func callJSON(t *testing.T, h http.HandlerFunc) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", "/", nil))
	var b map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	return rec.Code, b
}

func TestDaemonHealthAndCosignatureTransitions(t *testing.T) {
	logKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	logX, logY := verifier.PubXY(logKey)
	fl := &fakeLog{log: logOf("a", "b", "c"), key: logKey, origin: "honest-ear.log/v1"}
	srv := fl.server()
	defer srv.Close()

	d := &daemon{cfg: config{
		name: "w1", origin: "honest-ear.log/v1", logURL: srv.URL,
		key: wKey, logPubX: logX, logPubY: logY,
	}, st: &witnessState{}}

	// First poll: consistent first sight -> healthy + a cosignature available.
	d.once()
	if code, body := callJSON(t, d.handleHealth); code != 200 || body["ok"] != true {
		t.Fatalf("health after first sight = %d ok=%v, want 200/true", code, body["ok"])
	}
	if code, _ := callJSON(t, d.handleCosignature); code != 200 {
		t.Errorf("cosignature = %d, want 200", code)
	}

	// The log FORKS -> the witness refuses -> /health flips to 503.
	fl.set(logOf("a", "b", "X"))
	d.once()
	if code, body := callJSON(t, d.handleHealth); code != 503 || body["ok"] != false {
		t.Errorf("health after fork = %d ok=%v, want 503/false", code, body["ok"])
	}
	// The last good cosignature is still served (we keep it, don't serve the fork's).
	if code, _ := callJSON(t, d.handleCosignature); code != 200 {
		t.Errorf("cosignature after fork = %d, want 200 (last good kept)", code)
	}
}

// peerServer stands up a mock peer witness serving /cosignature for the given
// checkpoint (origin,size,root) signed by peerKey — what checkPeers consumes.
func peerServer(t *testing.T, origin string, size int, root [32]byte, peerKey *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()
	body := verifier.CheckpointBody(origin, size, root)
	sig, err := verifier.CosignCheckpoint(body, peerKey)
	if err != nil {
		t.Fatal(err)
	}
	px, py := verifier.PubXY(peerKey)
	mux := http.NewServeMux()
	mux.HandleFunc("/cosignature", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"witness": "peer", "witness_pub_x": hex.EncodeToString(px),
			"witness_pub_y": hex.EncodeToString(py), "cosignature": hex.EncodeToString(sig),
			"checkpoint_body": string(body),
		})
	})
	return httptest.NewServer(mux)
}

// The daemon's continuous cross-check: an AGREEing peer leaves /health healthy;
// a peer holding a DIVERGENT root at the same size latches equivocation_detected.
func TestDaemonPeerCrossCheck(t *testing.T) {
	origin := "honest-ear.log/v1"
	root := logOf("a", "b", "c").Root()
	peerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	px, py := verifier.PubXY(peerKey)

	// Our view = size 3, the genuine root. Peer agrees.
	ours := &witnessState{Origin: origin, Size: 3, Root: hex.EncodeToString(root[:])}
	agree := peerServer(t, origin, 3, root, peerKey)
	defer agree.Close()
	d := &daemon{cfg: config{name: "w1", origin: origin}, // nil client -> checkPeers defaults one
		peers: []peer{{name: "peer", url: agree.URL, pubX: px, pubY: py}},
		st:    ours, healthOK: true}
	d.checkPeers()
	code, body := callJSON(t, d.handleHealth)
	if body["equivocation_detected"] != false {
		t.Errorf("agreeing peer flagged equivocation: %+v", body)
	}
	if ps, _ := body["peers"].(map[string]any); ps == nil || ps["peer"] == nil {
		t.Errorf("peer status missing from /health: %+v", body)
	}
	_ = code

	// Now a peer holding a DIFFERENT root at the same size -> equivocation latched.
	forkRoot := logOf("a", "b", "X").Root()
	fork := peerServer(t, origin, 3, forkRoot, peerKey)
	defer fork.Close()
	d.peers = []peer{{name: "peer", url: fork.URL, pubX: px, pubY: py}}
	d.checkPeers()
	code2, body2 := callJSON(t, d.handleHealth)
	if body2["equivocation_detected"] != true {
		t.Errorf("divergent peer did NOT latch equivocation: %+v", body2)
	}
	if body2["ok"] != false || code2 != 503 {
		t.Errorf("equivocation should make /health unhealthy: code=%d body=%+v", code2, body2)
	}
}

// On a same-size split view, the daemon assembles a TRANSFERABLE proof from its own
// cosigned view + the divergent peer's, served at /equivocation-proof (404 before),
// and that proof verifies OFFLINE under the two pinned witness keys — so anyone, not
// just this witness, can confirm the log equivocated.
func TestDaemonServesEquivocationProof(t *testing.T) {
	origin := "honest-ear.log/v1"
	genuine := logOf("a", "b", "c").Root()
	ourKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ourX, ourY := verifier.PubXY(ourKey)
	ourBody := verifier.CheckpointBody(origin, 3, genuine)
	ourCosig, err := verifier.CosignCheckpoint(ourBody, ourKey)
	if err != nil {
		t.Fatal(err)
	}
	peerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	px, py := verifier.PubXY(peerKey)

	d := &daemon{
		cfg: config{name: "w1", origin: origin},
		st:  &witnessState{Origin: origin, Size: 3, Root: hex.EncodeToString(genuine[:])},
		latest: &pollResult{Body: ourBody, Cosignature: verifier.Cosignature{
			Witness: "w1", PubX: ourX, PubY: ourY, Sig: ourCosig,
		}},
		healthOK: true,
	}

	// Before any divergence: no proof.
	rr := httptest.NewRecorder()
	d.handleEquivocationProof(rr, httptest.NewRequest("GET", "/equivocation-proof", nil))
	if rr.Code != 404 {
		t.Fatalf("proof before divergence = %d, want 404", rr.Code)
	}

	// A peer holding a DIFFERENT root at the SAME size 3 -> proof gets assembled.
	fork := peerServer(t, origin, 3, logOf("a", "b", "X").Root(), peerKey)
	defer fork.Close()
	d.peers = []peer{{name: "peer", url: fork.URL, pubX: px, pubY: py}}
	d.checkPeers()

	rr = httptest.NewRecorder()
	d.handleEquivocationProof(rr, httptest.NewRequest("GET", "/equivocation-proof", nil))
	if rr.Code != 200 {
		t.Fatalf("proof after divergence = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var p equivProof
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatalf("proof json: %v", err)
	}
	// The served proof must verify OFFLINE under the two PINNED witness keys.
	cosigA, _ := hex.DecodeString(p.A.Cosignature)
	cosigB, _ := hex.DecodeString(p.B.Cosignature)
	ok, reason := verifier.VerifyEquivocation(
		[]byte(p.A.CheckpointBody), cosigA, ourX, ourY,
		[]byte(p.B.CheckpointBody), cosigB, px, py)
	if !ok {
		t.Fatalf("served proof does not verify under the pinned keys: %s", reason)
	}
}

// One-hop relay intake: a witness that PINNED the two witnesses adopts a POSTed proof
// (latching itself) — but ONLY if it verifies under OUR pinned keys. An unpinned
// witness or a tampered proof is rejected and does NOT latch (self-authenticating).
func TestDaemonAdoptsRelayedProof(t *testing.T) {
	origin := "honest-ear.log/v1"
	waKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wbKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	waX, waY := verifier.PubXY(waKey)
	wbX, wbY := verifier.PubXY(wbKey)

	ckpt := func(name string, k *ecdsa.PrivateKey, root [32]byte) equivCkpt {
		body := verifier.CheckpointBody(origin, 3, root)
		sig, err := verifier.CosignCheckpoint(body, k)
		if err != nil {
			t.Fatal(err)
		}
		px, py := verifier.PubXY(k)
		return equivCkpt{Witness: name, CheckpointBody: string(body), Cosignature: hex.EncodeToString(sig),
			WitnessPubX: hex.EncodeToString(px), WitnessPubY: hex.EncodeToString(py)}
	}
	proof := equivProof{Schema: equivProofSchema,
		A: ckpt("wa", waKey, logOf("a", "b", "c").Root()),
		B: ckpt("wb", wbKey, logOf("a", "b", "X").Root())}

	post := func(d *daemon, p equivProof) int {
		body, _ := json.Marshal(p)
		rr := httptest.NewRecorder()
		d.handleEquivocationIntake(rr, httptest.NewRequest("POST", "/equivocation-intake", bytes.NewReader(body)))
		return rr.Code
	}
	bothPinned := func() *daemon {
		return &daemon{cfg: config{name: "wc", origin: origin},
			peers: []peer{{name: "wa", pubX: waX, pubY: waY}, {name: "wb", pubX: wbX, pubY: wbY}},
			st:    &witnessState{Origin: origin}, healthOK: true}
	}

	// Adopt a valid relayed proof: 200, latched, stored for re-serving.
	d := bothPinned()
	if code := post(d, proof); code != 200 {
		t.Fatalf("valid relayed proof = %d, want 200", code)
	}
	if !d.equivocation || d.healthOK || d.proof == nil {
		t.Errorf("adopting did not latch/store: equiv=%v healthOK=%v proof=%v", d.equivocation, d.healthOK, d.proof != nil)
	}

	// Reject a proof naming a witness we did NOT pin (only wb pinned) — no latch.
	d2 := &daemon{cfg: config{name: "wc", origin: origin},
		peers: []peer{{name: "wb", pubX: wbX, pubY: wbY}}, st: &witnessState{Origin: origin}, healthOK: true}
	if code := post(d2, proof); code != 400 || d2.equivocation {
		t.Errorf("unpinned-witness proof: code=%d equiv=%v, want 400 + no latch", code, d2.equivocation)
	}

	// Reject a tampered proof (B body corrupted -> cosig fails) — no latch.
	bad := proof
	bad.B.CheckpointBody = proof.B.CheckpointBody + "x"
	d3 := bothPinned()
	if code := post(d3, bad); code != 400 || d3.equivocation {
		t.Errorf("tampered proof: code=%d equiv=%v, want 400 + no latch", code, d3.equivocation)
	}
}
