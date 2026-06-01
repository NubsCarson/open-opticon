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
