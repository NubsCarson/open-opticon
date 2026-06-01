package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	verifier "honest-ear/verifier"
)

func logOf(entries ...string) *verifier.MerkleLog {
	l := &verifier.MerkleLog{}
	for _, e := range entries {
		l.Add([]byte(e))
	}
	return l
}

func get(t *testing.T, h http.HandlerFunc, url string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", url, nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestCheckpointHandlerSignsCurrentRoot(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	load := func() (*verifier.MerkleLog, error) { return logOf("a", "b", "c"), nil }
	code, body := get(t, checkpointHandler(load, "honest-ear.log/v1", key), "/checkpoint")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	// The served checkpoint's signature must verify under the served log key.
	cpBody := []byte(body["body"].(string))
	sig, _ := hex.DecodeString(body["sig"].(string))
	px, _ := hex.DecodeString(body["log_pub_x"].(string))
	py, _ := hex.DecodeString(body["log_pub_y"].(string))
	if !verifier.VerifyCheckpointSig(cpBody, sig, px, py) {
		t.Error("served checkpoint signature does not verify under the served key")
	}
	if body["size"].(float64) != 3 {
		t.Errorf("size = %v, want 3", body["size"])
	}
}

func TestCheckpointHandlerSurfacesLoadError(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	load := func() (*verifier.MerkleLog, error) { return nil, errBad }
	code, body := get(t, checkpointHandler(load, "o", key), "/checkpoint")
	if code != 500 || body["error"] == nil {
		t.Errorf("expected 500 + error, got %d %v", code, body)
	}
}

func TestConsistencyHandlerCases(t *testing.T) {
	load := func() (*verifier.MerkleLog, error) { return logOf("a", "b", "c", "d", "e"), nil }
	h := consistencyHandler(load)

	// from in range: a proof that VerifyConsistency accepts against the real roots.
	code, body := get(t, h, "/consistency?from=3")
	if code != 200 {
		t.Fatalf("from=3 status %d", code)
	}
	if body["new_size"].(float64) != 5 {
		t.Errorf("new_size = %v, want 5", body["new_size"])
	}
	oldRoot := logOf("a", "b", "c").Root()
	newRoot := mustRoot(t, body["new_root"].(string))
	var proof [][32]byte
	for _, p := range body["proof"].([]any) {
		proof = append(proof, mustRoot(t, p.(string)))
	}
	if !verifier.VerifyConsistency(3, 5, proof, oldRoot, newRoot) {
		t.Error("served consistency proof does not verify 3 -> 5")
	}

	// from == size: valid, empty proof (boundary).
	code, body = get(t, h, "/consistency?from=5")
	if code != 200 {
		t.Fatalf("from=5 status %d", code)
	}
	if len(body["proof"].([]any)) != 0 {
		t.Errorf("from==size should yield an empty proof, got %v", body["proof"])
	}

	// from > size: rejected.
	code, _ = get(t, h, "/consistency?from=99")
	if code != 400 {
		t.Errorf("from>size status = %d, want 400", code)
	}

	// bad ?from: rejected.
	code, _ = get(t, h, "/consistency?from=notanumber")
	if code != 400 {
		t.Errorf("bad ?from status = %d, want 400", code)
	}
}

func mustRoot(t *testing.T, h string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad root hex %q", h)
	}
	var r [32]byte
	copy(r[:], b)
	return r
}

// errBad is a sentinel load error.
var errBad = &loadErr{}

type loadErr struct{}

func (*loadErr) Error() string { return "boom" }
