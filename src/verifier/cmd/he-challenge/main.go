// he-challenge — live challenge-response verifier.
//
// This is the load-bearing answer to the static-QR / skimmer concern: trust
// comes from a FRESH nonce signed live by the device key, not from a copyable
// sticker. Flow:
//
//  1. GET  /challenge            -> server mints a fresh 32-byte nonce + session
//  2. (device/sim signs that exact nonce, producing a bound-output bundle)
//  3. POST /attest?session=<id>  -> server verifies signature+freshness+counter
//
// A QR encoding {url, session, nonce} is rendered to the terminal (via the
// `qrencode` CLI if present) so the flow can be driven from a phone.
// Dependency-free Go stdlib; state is in-memory (PoC scope).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"sync"
	"time"

	verifier "honest-ear/verifier"
)

type session struct {
	nonce       []byte
	createdAt   time.Time
	lastCounter uint64
}

type server struct {
	mu       sync.Mutex
	sessions map[string]*session
	baseURL  string
	// optional endorsement pin (device-identity gate)
	pinX, pinY []byte
	ttl        time.Duration
}

func main() {
	addr := flag.String("addr", ":8090", "listen address")
	base := flag.String("base-url", "", "externally reachable base URL (for the QR); defaults to http://<addr>")
	pinX := flag.String("pin-x", "", "pinned endorsement pub X (hex), optional")
	pinY := flag.String("pin-y", "", "pinned endorsement pub Y (hex), optional")
	flag.Parse()

	s := &server{
		sessions: map[string]*session{},
		baseURL:  *base,
		ttl:      5 * time.Minute,
	}
	if s.baseURL == "" {
		s.baseURL = "http://localhost" + *addr
	}
	if *pinX != "" {
		x, err := hex.DecodeString(*pinX)
		if err != nil {
			log.Fatalf("bad --pin-x: %v", err)
		}
		s.pinX = x
	}
	if *pinY != "" {
		y, err := hex.DecodeString(*pinY)
		if err != nil {
			log.Fatalf("bad --pin-y: %v", err)
		}
		s.pinY = y
	}

	http.HandleFunc("/challenge", s.handleChallenge)
	http.HandleFunc("/attest", s.handleAttest)
	http.HandleFunc("/", s.handleRoot)

	log.Printf("Honest Ear challenge verifier listening on %s (base %s)", *addr, s.baseURL)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *server) handleChallenge(w http.ResponseWriter, _ *http.Request) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "rng failure", 500)
		return
	}
	sid := randHex(8)

	s.mu.Lock()
	s.sessions[sid] = &session{nonce: nonce, createdAt: time.Now()}
	s.gcLocked()
	s.mu.Unlock()

	nonceHex := hex.EncodeToString(nonce)
	attestURL := fmt.Sprintf("%s/attest?session=%s", s.baseURL, sid)
	renderQR(attestURL + "&nonce=" + nonceHex)
	log.Printf("issued challenge session=%s nonce=%s", sid, nonceHex)
	writeJSON(w, 200, map[string]string{
		"session": sid, "nonce": nonceHex, "attest_url": attestURL,
	})
}

func (s *server) handleAttest(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("session")
	s.mu.Lock()
	sess := s.sessions[sid]
	s.mu.Unlock()
	if sess == nil {
		writeJSON(w, 404, map[string]string{"verdict": "FAIL", "reason": "unknown or expired session"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // bound the body (DoS guard)
	var b verifier.Bundle
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, 400, map[string]string{"verdict": "FAIL", "reason": "bad bundle: " + err.Error()})
		return
	}

	res := verifier.VerifyBundle(b, verifier.Options{
		ExpectedNonce: sess.nonce,
		PinPubX:       s.pinX,
		PinPubY:       s.pinY,
		LastCounter:   sess.lastCounter,
	})

	out := map[string]any{"verdict": "FAIL", "reason": res.Reason}
	if res.OK {
		s.mu.Lock()
		sess.lastCounter = res.Predicate.Counter
		s.mu.Unlock()
		out["verdict"] = "PASS"
		out["event"] = res.Predicate.EventName()
		out["presence"] = res.Predicate.Presence
		out["voice_active"] = res.Predicate.VoiceActive
		out["counter"] = res.Predicate.Counter
	}
	log.Printf("attest session=%s verdict=%v reason=%s", sid, out["verdict"], res.Reason)
	writeJSON(w, 200, out)
}

func (s *server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "Honest Ear live challenge verifier.\n"+
		"  GET  /challenge            -> fresh nonce + session\n"+
		"  POST /attest?session=<id>  -> verify a bound-output bundle\n")
}

func (s *server) gcLocked() {
	now := time.Now()
	for k, v := range s.sessions {
		if now.Sub(v.createdAt) > s.ttl {
			delete(s.sessions, k)
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// renderQR prints a scannable QR if the `qrencode` CLI is available; otherwise
// it prints the payload string so the operator can show/scan it another way.
func renderQR(payload string) {
	if path, err := exec.LookPath("qrencode"); err == nil {
		cmd := exec.Command(path, "-t", "ANSIUTF8", payload)
		out, err := cmd.Output()
		if err == nil {
			fmt.Printf("\n%s\n", out)
			return
		}
	}
	fmt.Printf("\n[challenge] %s\n(install `qrencode` to render this as a scannable QR)\n\n", payload)
}
