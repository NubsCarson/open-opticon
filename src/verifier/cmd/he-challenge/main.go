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
// A QR is rendered to the terminal (via the `qrencode` CLI if present) that
// opens a mobile verifier page (/v) on a phone: the page polls /status and shows
// a plain-language live PASS/FAIL verdict for that session, so a non-expert can
// watch the device prove itself. Dependency-free Go stdlib; state is in-memory
// (PoC scope).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	verifier "honest-ear/verifier"
)

// maxSessions caps in-memory sessions so an unauthenticated /challenge flood
// cannot grow memory without bound (sessions also expire after ttl).
const maxSessions = 10000

type session struct {
	nonce       []byte
	createdAt   time.Time
	lastCounter uint64
	// latest verdict for the mobile verifier page (empty until first attest)
	verdict, event, reason string
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
	http.HandleFunc("/status", s.handleStatus)
	http.HandleFunc("/v", s.handleVerifyPage)
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
	s.gcLocked()
	if len(s.sessions) >= maxSessions { // bound memory under a /challenge flood
		s.mu.Unlock()
		writeJSON(w, 503, map[string]string{"error": "too many active sessions, retry shortly"})
		return
	}
	s.sessions[sid] = &session{nonce: nonce, createdAt: time.Now()}
	s.mu.Unlock()

	nonceHex := hex.EncodeToString(nonce)
	attestURL := fmt.Sprintf("%s/attest?session=%s", s.baseURL, sid)
	// The QR opens the mobile verifier page so a phone can watch the verdict live.
	// Only the session id is needed; the device gets the nonce from the JSON below.
	renderQR(fmt.Sprintf("%s/v?session=%s", s.baseURL, sid))
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

	// Decide the verdict and advance the anti-replay counter atomically under the
	// lock. VerifyBundle ran against a snapshot of lastCounter, so two concurrent
	// attests could both clear Gate 3 against the same snapshot; re-checking and
	// advancing here makes the per-session compare-and-advance atomic. The same
	// critical section guards against the session being GC'd mid-verification.
	ok, reason := res.OK, res.Reason
	s.mu.Lock()
	_, live := s.sessions[sid]
	switch {
	case !live:
		// session expired during verification: report the verdict, don't store it
	case ok && res.Predicate.Counter <= sess.lastCounter:
		ok = false
		reason = fmt.Sprintf("counter %d not greater than last seen %d (concurrent replay)",
			res.Predicate.Counter, sess.lastCounter)
	case ok:
		sess.lastCounter = res.Predicate.Counter
	}
	verdict, event := "FAIL", ""
	if ok {
		verdict, event = "PASS", res.Predicate.EventName()
	}
	if live {
		sess.verdict, sess.event, sess.reason = verdict, event, reason
	}
	s.mu.Unlock()

	out := map[string]any{"verdict": verdict, "reason": reason}
	if ok {
		out["event"] = event
		out["presence"] = res.Predicate.Presence
		out["voice_active"] = res.Predicate.VoiceActive
		out["counter"] = res.Predicate.Counter
	}
	log.Printf("attest session=%s verdict=%s reason=%s", sid, verdict, reason)
	writeJSON(w, 200, out)
}

func (s *server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "Honest Ear live challenge verifier.\n"+
		"  GET  /challenge            -> fresh nonce + session\n"+
		"  POST /attest?session=<id>  -> verify a bound-output bundle\n"+
		"  GET  /v?session=<id>       -> mobile verifier page (scan the QR)\n"+
		"  GET  /status?session=<id>  -> latest verdict (JSON)\n")
}

// handleStatus reports the latest verdict for a session so the mobile page can
// poll it: state is "pending" until the device attests, then "done".
func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	sess := s.sessions[r.URL.Query().Get("session")]
	var out map[string]string
	switch {
	case sess == nil:
		out = map[string]string{"state": "unknown"}
	case sess.verdict == "":
		out = map[string]string{"state": "pending"}
	default:
		out = map[string]string{"state": "done", "verdict": sess.verdict,
			"event": sess.event, "reason": sess.reason}
	}
	s.mu.Unlock()
	writeJSON(w, 200, out)
}

// handleVerifyPage serves a mobile-friendly page that polls /status and shows a
// plain-language live verdict. No JS framework, no external assets.
func (s *server) handleVerifyPage(w http.ResponseWriter, r *http.Request) {
	sid := html.EscapeString(r.URL.Query().Get("session"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, strings.ReplaceAll(verifyPage, "{{SID}}", sid))
}

const verifyPage = `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>open-opticon — verify</title><style>
:root{--bg:#1a1b26;--fg:#c0caf5;--dim:#787c99;--g:#9ece6a;--r:#f7768e;--b:#7dcfff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
min-height:100vh;display:flex;flex-direction:column;align-items:center;
justify-content:center;text-align:center;padding:28px}
h1{font-size:1.1rem;color:var(--dim);font-weight:600;letter-spacing:.02em;margin:0 0 28px}
#card{font-size:4.6rem;font-weight:800;line-height:1;margin:6px 0}
#sub{font-size:1.05rem;color:var(--fg);margin-top:6px;min-height:1.4em}
#why{color:var(--dim);font-size:.9rem;margin-top:18px;max-width:30ch}
.spin{width:46px;height:46px;border-radius:50%;border:4px solid #2a2e44;
border-top-color:var(--b);animation:s 1s linear infinite}@keyframes s{to{transform:rotate(360deg)}}
.foot{position:fixed;bottom:16px;color:var(--dim);font-size:.75rem}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}</style></head><body>
<h1>open-opticon · live verification</h1>
<div id="card"><div class="spin"></div></div>
<div id="sub">waiting for the device to prove itself…</div>
<div id="why"></div>
<div class="foot">session <span class="mono">{{SID}}</span></div>
<script>
const sid=new URLSearchParams(location.search).get("session");
const card=document.getElementById("card"),sub=document.getElementById("sub"),why=document.getElementById("why");
async function poll(){
 try{const r=await fetch("/status?session="+encodeURIComponent(sid));const d=await r.json();
  if(d.state==="done"){
   if(d.verdict==="PASS"){card.textContent="✓";card.style.color="var(--g)";
    sub.textContent="Verified — "+(d.event||"event")+" detected";
    why.textContent="The genuine, attested firmware produced this exact result for a fresh challenge. No audio left the device.";}
   else{card.textContent="✗";card.style.color="var(--r)";
    sub.textContent="Rejected";why.textContent=d.reason||"verification failed";}
   return;}
  if(d.state==="unknown"){card.textContent="?";card.style.color="var(--dim)";
   sub.textContent="unknown or expired session";return;}
 }catch(e){}
 setTimeout(poll,1000);
}
poll();
</script></body></html>`

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
