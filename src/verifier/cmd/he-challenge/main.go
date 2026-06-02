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
// watch the device prove itself. With `--sim <he-attest-sim>`, the home page also
// gets a "simulate a device" button (POST /simulate) that signs the nonce with
// the host simulator, so the whole loop completes in the browser with no separate
// device. Dependency-free Go stdlib; state is in-memory (PoC scope).
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
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
	// proof backs the walk-up page's 5 plain-language answers on a PASS; nil
	// until a bundle verifies. Every field here is data the live check actually
	// produced — so each "show me the proof" panel shows a real artifact.
	proof *proofView
}

// proofView is the verified, layperson-facing evidence for one session: the
// decoded predicate the device signed plus the raw bundle that crossed the wire.
// It carries ONLY what the live challenge flow (gates 0-3) genuinely proves; the
// page is careful to mark firmware/hardware-tier claims as not proven by this
// check. See the walk-up page copy for the honest tiering.
type proofView struct {
	Event       string `json:"event"`
	Presence    uint64 `json:"presence"`
	VoiceActive bool   `json:"voice_active"`
	Frames      uint64 `json:"frames"`
	WindowMs    uint64 `json:"window_ms"`
	Counter     uint64 `json:"counter"`
	ConfigHash  string `json:"config_hash"` // hex; SHA-256 of the detector policy
	InputHash   string `json:"input_hash"`  // hex; SHA-256 of the analyzed window
	Payload     string `json:"payload"`     // hex; the exact signed bytes
	Sig         string `json:"sig"`         // hex; 64-byte r||s
	PubX        string `json:"pub_x"`       // hex
	PubY        string `json:"pub_y"`       // hex
	// Pinned is true if this server enforced the endorsement pin (gate 0), i.e.
	// the verdict is tied to the ENROLLED device key, not merely a valid key.
	Pinned bool `json:"pinned"`
}

type server struct {
	mu       sync.Mutex
	sessions map[string]*session
	baseURL  string
	// optional endorsement pin (device-identity gate)
	pinX, pinY []byte
	ttl        time.Duration
	// optional in-browser demo: sign the challenge with the host simulator so /v
	// reaches a real verdict without a separate device. Empty = disabled.
	simPath, clipPath string
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(),
			"he-challenge — live nonce/challenge server + mobile verifier page (/v).\n\n"+
				"usage: he-challenge [flags]   then open http://<addr>/ (operator) or /v (phone)\n\nflags:\n")
		flag.PrintDefaults()
	}
	addr := flag.String("addr", ":8090", "listen address")
	base := flag.String("base-url", "", "externally reachable base URL (for the QR); defaults to http://<addr>")
	pinX := flag.String("pin-x", "", "pinned endorsement pub X (hex), optional")
	pinY := flag.String("pin-y", "", "pinned endorsement pub Y (hex), optional")
	sim := flag.String("sim", "", "path to he-attest-sim — enables a 'simulate a device' button so the loop completes in the browser (optional)")
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

	if *sim != "" {
		clip, err := writeAlarmClip()
		if err != nil {
			log.Fatalf("could not create demo clip: %v", err)
		}
		s.simPath, s.clipPath = *sim, clip
		http.HandleFunc("/simulate", s.handleSimulate)
	}

	http.HandleFunc("/challenge", s.handleChallenge)
	http.HandleFunc("/attest", s.handleAttest)
	http.HandleFunc("/status", s.handleStatus)
	http.HandleFunc("/v", s.handleVerifyPage)
	http.HandleFunc("/", s.handleRoot)

	log.Printf("open-opticon challenge verifier listening on %s (base %s)", *addr, s.baseURL)
	log.Fatal(cli.Serve(*addr))
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
		cli.WriteJSON(w, 503, map[string]string{"error": "too many active sessions, retry shortly"})
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
	cli.WriteJSON(w, 200, map[string]string{
		"session": sid, "nonce": nonceHex, "attest_url": attestURL,
	})
}

func (s *server) handleAttest(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("session")
	s.mu.Lock()
	sess := s.sessions[sid]
	s.mu.Unlock()
	if sess == nil {
		cli.WriteJSON(w, 404, map[string]string{"verdict": "FAIL", "reason": "unknown or expired session"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // bound the body (DoS guard)
	var b verifier.Bundle
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		cli.WriteJSON(w, 400, map[string]string{"verdict": "FAIL", "reason": "bad bundle: " + err.Error()})
		return
	}
	cli.WriteJSON(w, 200, s.verifyAndRecord(sid, sess, b))
}

// handleSimulate signs the session's nonce with the host simulator and runs it
// through the same verify+record path, so the /v page reaches a real verdict in
// the browser without a separate device. Only registered when --sim is set.
func (s *server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("session")
	s.mu.Lock()
	sess := s.sessions[sid]
	ctr := uint64(0)
	if sess != nil {
		ctr = sess.lastCounter + 1
	}
	s.mu.Unlock()
	if sess == nil {
		cli.WriteJSON(w, 404, map[string]string{"verdict": "FAIL", "reason": "unknown or expired session"})
		return
	}
	out, err := exec.Command(s.simPath, s.clipPath, hex.EncodeToString(sess.nonce),
		fmt.Sprint(ctr)).Output()
	if err != nil {
		cli.WriteJSON(w, 500, map[string]string{"verdict": "FAIL", "reason": "simulator failed: " + err.Error()})
		return
	}
	var b verifier.Bundle
	if err := json.Unmarshal(out, &b); err != nil {
		cli.WriteJSON(w, 500, map[string]string{"verdict": "FAIL", "reason": "bad sim output: " + err.Error()})
		return
	}
	cli.WriteJSON(w, 200, s.verifyAndRecord(sid, sess, b))
}

// verifyAndRecord verifies a bundle for a session and atomically advances the
// anti-replay counter + records the verdict (shared by /attest and /simulate).
// VerifyBundle runs against a snapshot of lastCounter, so two concurrent attests
// could both clear Gate 3; re-checking under the lock makes the per-session
// compare-and-advance atomic and also guards a session GC'd mid-verification.
func (s *server) verifyAndRecord(sid string, sess *session, b verifier.Bundle) map[string]any {
	// Snapshot the per-session counter under the lock — reading it unlocked here
	// would race the locked compare-and-advance write below under concurrent
	// attests. VerifyBundle's counter check is only a pre-filter; the lock-held
	// re-check at the switch is authoritative. (nonce is set once at session
	// creation and never mutated, so it is safe to read unlocked.)
	s.mu.Lock()
	snapCounter := sess.lastCounter
	s.mu.Unlock()
	res := verifier.VerifyBundle(b, verifier.Options{
		ExpectedNonce: sess.nonce, PinPubX: s.pinX, PinPubY: s.pinY, LastCounter: snapCounter,
	})
	ok, reason := res.OK, res.Reason
	s.mu.Lock()
	_, live := s.sessions[sid]
	switch {
	case !live:
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
		if ok {
			p := res.Predicate
			sess.proof = &proofView{
				Event: event, Presence: p.Presence, VoiceActive: p.VoiceActive,
				Frames: p.Frames, WindowMs: p.WindowMs, Counter: p.Counter,
				ConfigHash: hex.EncodeToString(p.ConfigHash),
				InputHash:  hex.EncodeToString(p.InputHash),
				Payload:    b.Payload, Sig: b.Sig, PubX: b.PubX, PubY: b.PubY,
				Pinned: len(s.pinX) > 0 && len(s.pinY) > 0,
			}
		} else {
			// A later FAIL (e.g. a replay) must not leave a prior PASS's proof
			// attached — keep /status self-consistent with the recorded verdict.
			sess.proof = nil
		}
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
	return out
}

// writeAlarmClip writes a 1 s 3.1 kHz s16le-mono tone to a temp file — the demo
// audio the --sim "simulate a device" path feeds to the host simulator.
func writeAlarmClip() (string, error) {
	const rate = 16000
	buf := make([]byte, rate*2)
	for i := 0; i < rate; i++ {
		v := int16(8000 * math.Sin(2*math.Pi*3100*float64(i)/float64(rate)))
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(v))
	}
	f, err := os.CreateTemp("", "he-clip-*.pcm")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(buf); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	simDisplay := "none" // the "simulate a device" button only appears with --sim
	if s.simPath != "" {
		simDisplay = "inline-flex"
	}
	_, _ = io.WriteString(w, strings.ReplaceAll(homePage, "{{SIM}}", simDisplay))
}

const homePage = `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>open-opticon — verification server</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%2309090b'/><circle cx='16' cy='16' r='8.5' fill='none' stroke='%23fafafa' stroke-width='2'/><circle cx='16' cy='16' r='2.6' fill='%23fafafa'/></svg>">
<style>
:root{--bg:#09090b;--card:#0b0b0e;--line:#26262b;--fg:#fafafa;--dim:#a1a1aa;--dim2:#71717a;--b:#60a5fa;--g:#4ade80}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);letter-spacing:-.011em;
font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.6;
display:flex;flex-direction:column;align-items:center;min-height:100vh;padding:48px 20px}
.wrap{width:100%;max-width:620px}
.eyebrow{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;text-transform:uppercase;
letter-spacing:.09em;color:var(--dim2)}
h1{font-size:1.6rem;font-weight:650;margin:10px 0 8px;letter-spacing:-.02em}
p.sub{color:var(--dim);margin:0 0 26px}
button{appearance:none;border:0;background:var(--fg);color:#0a0a0a;font:inherit;font-weight:500;
font-size:14px;height:42px;padding:0 18px;border-radius:8px;cursor:pointer}
button:hover{background:#e4e4e7}
#out{display:none;margin-top:26px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:14px}
.k{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--dim2);text-transform:uppercase;letter-spacing:.06em}
.val{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;word-break:break-all;margin-top:4px;color:var(--fg)}
a.open{display:inline-flex;align-items:center;gap:8px;height:40px;padding:0 16px;border:1px solid var(--line);
border-radius:8px;color:var(--fg);text-decoration:none;font-size:14px}
a.open:hover{border-color:#3a3a40;background:#161619}
pre{margin:8px 0 0;background:#101014;border:1px solid var(--line);border-radius:8px;padding:12px 14px;
overflow-x:auto;font-size:12.5px;color:#d4d4d8}
pre .c{color:var(--dim2)} pre .n{color:var(--b)}
.foot{color:var(--dim2);font-size:12.5px;margin-top:22px;line-height:1.7}
.foot code{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--dim)}
</style></head><body>
<div class="wrap">
  <p class="eyebrow">open-opticon · live verification server</p>
  <h1>Mint a challenge. Verify the device.</h1>
  <p class="sub">Trust comes from a fresh nonce signed live by the device key — not a static sticker.
     Start a challenge, sign it on the device, and watch the verdict.</p>
  <button id="go">New challenge</button>
  <button id="sim" style="display:{{SIM}};margin-left:8px;background:transparent;border:1px solid var(--line);color:var(--fg)">Simulate a device</button>
  <div id="out">
    <div class="card" id="simout" style="display:none;border-color:#1f3d2b"><div class="k" style="color:var(--g)">simulated device</div><div class="val" id="simmsg"></div></div>
    <div class="card"><div class="k">verifier page (open on a phone, or click)</div>
      <div class="val"><a class="open" id="vlink" target="_blank">Open the verifier page →</a></div></div>
    <div class="card"><div class="k">fresh nonce</div><div class="val" id="nonce"></div></div>
    <div class="card"><div class="k">on the device</div>
<pre><span class="c"># produce a bound output for this exact nonce</span>
he_host /usr/bin/clip.pcm <span class="n" id="cn"></span>

<span class="c"># or post a bundle.json straight to the verifier</span>
curl -X POST "<span class="n" id="cu"></span>" --data @bundle.json</pre></div>
  </div>
  <p class="foot">API: <code>GET /challenge</code> · <code>POST /attest?session=&lt;id&gt;</code> ·
     <code>GET /v?session=&lt;id&gt;</code> · <code>GET /status?session=&lt;id&gt;</code>.
     A QR for the verifier page is also printed in this server's terminal.</p>
</div>
<script>
let sid="";
document.getElementById("go").onclick=async()=>{
  const d=await (await fetch("/challenge")).json();
  sid=d.session;
  document.getElementById("vlink").href="/v?session="+d.session;
  document.getElementById("nonce").textContent=d.nonce;
  document.getElementById("cn").textContent=d.nonce;
  document.getElementById("cu").textContent=d.attest_url;
  document.getElementById("simout").style.display="none";
  document.getElementById("out").style.display="block";
};
document.getElementById("sim").onclick=async()=>{
  if(!sid){alert("Mint a challenge first.");return;}
  const r=await fetch("/simulate?session="+encodeURIComponent(sid),{method:"POST"});
  const d=await r.json();
  const msg=document.getElementById("simmsg");
  msg.textContent=d.verdict==="PASS"
    ? "✓ "+d.verdict+" — "+(d.event||"event")+". Open the verifier page above to see it."
    : "✗ "+(d.reason||"failed");
  document.getElementById("simout").style.display="block";
};
</script></body></html>`

// statusResp is the /status payload the mobile walk-up page polls. On a PASS it
// carries the proof so the page can answer the program's 5 questions with the
// literal verified artifacts (each "show me the proof" panel), not prose alone.
type statusResp struct {
	State   string     `json:"state"` // unknown | pending | done
	Verdict string     `json:"verdict,omitempty"`
	Event   string     `json:"event,omitempty"`
	Reason  string     `json:"reason,omitempty"`
	Proof   *proofView `json:"proof,omitempty"`
}

// handleStatus reports the latest verdict for a session so the mobile page can
// poll it: state is "pending" until the device attests, then "done".
func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	sess := s.sessions[r.URL.Query().Get("session")]
	var out statusResp
	switch {
	case sess == nil:
		out = statusResp{State: "unknown"}
	case sess.verdict == "":
		out = statusResp{State: "pending"}
	default:
		// proof is a pointer set once under the lock on PASS and never mutated
		// after, so handing out the same pointer is safe for the read-only page.
		out = statusResp{State: "done", Verdict: sess.verdict,
			Event: sess.event, Reason: sess.reason, Proof: sess.proof}
	}
	s.mu.Unlock()
	cli.WriteJSON(w, 200, out)
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
<title>open-opticon — verify</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%2309090b'/><circle cx='16' cy='16' r='8.5' fill='none' stroke='%23fafafa' stroke-width='2'/><circle cx='16' cy='16' r='2.6' fill='%23fafafa'/></svg>"><style>
:root{--bg:#09090b;--card:#0b0b0e;--line:#26262b;--fg:#fafafa;--dim:#a1a1aa;--dim2:#71717a;--g:#4ade80;--r:#f87171;--b:#60a5fa;--amber:#fbbf24}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);letter-spacing:-.011em;
font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.55;
min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:36px 18px 64px}
.wrap{width:100%;max-width:540px;text-align:center}
h1{font-size:1.05rem;color:var(--dim);font-weight:600;letter-spacing:.02em;margin:0 0 22px}
#card{font-size:4.4rem;font-weight:800;line-height:1;margin:6px 0}
#sub{font-size:1.05rem;color:var(--fg);margin-top:6px;min-height:1.4em;font-weight:600}
#why{color:var(--dim);font-size:.92rem;margin:14px auto 0;max-width:34ch}
.spin{width:44px;height:44px;border-radius:50%;border:4px solid #26262b;
border-top-color:var(--b);animation:s 1s linear infinite;display:inline-block}@keyframes s{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){.spin{animation:none}}
.scope{display:none;margin:22px auto 6px;max-width:40ch;color:var(--dim);font-size:.86rem}
#answers{display:none;margin-top:18px;text-align:left}
.qa{background:var(--card);border:1px solid var(--line);border-radius:11px;padding:15px 16px;margin-bottom:12px}
.qa .q{font-weight:650;font-size:.97rem;margin-bottom:5px}
.qa .a{color:var(--dim);font-size:.92rem}
.badge{display:inline-block;margin-top:9px;font-size:11px;font-weight:600;letter-spacing:.02em;
padding:3px 9px;border-radius:999px;border:1px solid var(--line)}
.badge.proven{color:var(--g);border-color:#1f3d2b;background:#0c1b12}
.badge.design{color:var(--amber);border-color:#4a3a12;background:#1c1606}
.badge.access{color:var(--b);border-color:#1e2f4a;background:#0a121f}
details{margin-top:11px}
summary{cursor:pointer;color:var(--b);font-size:.85rem;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸ ";color:var(--dim2)}
details[open] summary::before{content:"▾ "}
.cap{color:var(--dim);font-size:.83rem;margin:9px 0}
pre{background:#101014;border:1px solid var(--line);border-radius:8px;padding:11px 12px;
overflow-x:auto;font-size:12px;line-height:1.5;color:#d4d4d8;margin:0;
font-family:ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
pre .k{color:var(--dim2)}
.line{font-size:.83rem;margin-top:8px}
.line.ok{color:var(--g)} .line.warn{color:var(--amber)}
.foot{color:var(--dim2);font-size:.74rem;margin-top:26px}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}</style></head><body>
<div class="wrap">
<h1>open-opticon · live verification</h1>
<noscript><div id="sub">This live verifier needs JavaScript enabled to poll the result.</div></noscript>
<div id="live" role="status" aria-live="polite" aria-atomic="true">
<div id="card"><div class="spin"></div></div>
<div id="sub">waiting for the device to prove itself…</div></div>
<div id="why"></div>
<div class="scope" id="scope">✓ a key the device controls signed this exact verdict, live, for your one-time
challenge — it was not replayed or altered. tap any answer to see the proof and its limits.</div>
<div id="answers"></div>
<div class="foot">session <span class="mono">{{SID}}</span></div>
</div>
<script>
var sid=new URLSearchParams(location.search).get("session");
var card=document.getElementById("card"),sub=document.getElementById("sub"),why=document.getElementById("why");
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){
 return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c];});}
function kv(k,v){return "<span class='k'>"+esc(k)+":</span> "+esc(v)+"\n";}
function evName(p){return p.event||"an event";}
// The five questions the credible-sensors program asks. Answers + tiers are
// grounded in what the LIVE check proves; firmware/hardware-tier claims are
// marked so a green page never implies more than the signature carries.
function cards(p){return [
 {q:"1 · what gets captured?",
  a:"sound is analyzed for one thing — "+esc(evName(p))+". you get a verdict, not a recording.",
  badge:["proven","✓ proven by this check"],
  art:kv("event",p.event)+kv("presence",p.presence)+kv("voice_active",p.voice_active)+kv("frames",p.frames)+kv("window_ms",p.window_ms)+kv("input_hash",p.input_hash),
  cap:"the device signed this verdict, not audio. input_hash is a SHA-256 fingerprint of the exact window analyzed — it names the input without storing it.",
  ok:"the signed output is a small event verdict, not a recording or transcript.",
  warn:"that the raw audio is wiped inside the chip and never reaches the OS is firmware behavior — proven on QEMU; on a shipped unit it rests on hardware attestation + public source audit."},
 {q:"2 · where does it go?",
  a:"the bundle your phone just checked is a signed verdict with no audio field in it — that is the whole artifact.",
  badge:["proven","✓ proven by this check"],
  art:kv("payload",p.payload)+kv("sig",p.sig)+kv("pub_x",p.pub_x)+kv("pub_y",p.pub_y),
  cap:"this is the exact bundle posted for your challenge: a signature over the verdict. there is no audio field anywhere in it.",
  ok:"the bundle carries only a signed verdict — it has no audio field or channel.",
  warn:"that the device has no SEPARATE covert channel emitting audio is not provable from one signature — it rests on firmware measurement (attestation) + public source audit, like the wipe in cards 1 and 4. a second microphone or physical side-channel is out of scope entirely."},
 {q:"3 · who can access or release it?",
  a:"no one. nothing capturable is kept, so there is nothing to release. "+(p.pinned?"only the enrolled device's key can mint a valid verdict, and it cannot be replayed.":"only a key the device controls can mint a valid verdict, and it cannot be replayed."),
  badge:["access","○ integrity only"],
  art:kv("pub_x",p.pub_x)+kv("pub_y",p.pub_y)+kv("pinned to enrolled device",p.pinned),
  cap:p.pinned?"this server pinned the verdict to the enrolled device key above.":"this server did not pin a device key, so this proves genuine published code ran — not which physical device.",
  ok:"only the holder of this key can produce a verdict, and replays are rejected (the counter must advance).",
  warn:"opticon does not implement a 'who may read X' policy because there is no retained X. tying a verdict to a specific physical unit needs a non-extractable hardware key (i.MX CAAM / ST element) — not proven on this unit."},
 {q:"4 · how long is it kept?",
  a:"not kept. the audio is overwritten with zeros inside the enclave the instant the verdict is computed — its lifetime is milliseconds.",
  badge:["design","△ by design — not proven on this unit"],
  art:kv("counter (only state kept across windows)",p.counter)+kv("input_hash (a fingerprint, not audio)",p.input_hash),
  cap:"the only state kept across windows is this monotonic counter — it carries no audio. the wipe itself is firmware behavior you audit from source.",
  ok:"the live check shows the counter advancing (anti-replay); no audio is in anything that crossed the wire.",
  warn:"the in-enclave zeroize is firmware behavior — proven on QEMU and by reading he_audio_ta.c; on a shipped unit it rests on hardware attestation."},
 {q:"5 · how is it used?",
  a:"to compute this coarse verdict under a published policy. the rules that decide what counts are fingerprinted into the signature, so you can audit them from source.",
  badge:["proven","✓ proven by this check"],
  art:kv("config_hash (SHA-256 of the detector policy)",p.config_hash),
  cap:"config_hash is carried inside the signed payload, so the device cannot quietly use different rules than the published ones.",
  ok:"the policy is bound into the signature and is auditable from source; there is no hidden knob.",
  warn:"config_hash makes the policy checkable, not correct — the detector is a heuristic, not an audited model."}
];}
function render(p){
 var c=cards(p),h="";
 for(var i=0;i<c.length;i++){var x=c[i];
  h+="<div class='qa'><div class='q'>"+esc(x.q)+"</div><div class='a'>"+x.a+"</div>"+
     "<span class='badge "+x.badge[0]+"'>"+esc(x.badge[1])+"</span>"+
     "<details><summary>show me the proof</summary>"+
     "<div class='cap'>"+esc(x.cap)+"</div><pre>"+x.art+"</pre>"+
     "<div class='line ok'>✓ "+esc(x.ok)+"</div>"+
     "<div class='line warn'>△ "+esc(x.warn)+"</div></details></div>";}
 document.getElementById("answers").innerHTML=h;
 document.getElementById("answers").style.display="block";
 document.getElementById("scope").style.display="block";
}
async function poll(){
 try{var r=await fetch("/status?session="+encodeURIComponent(sid));var d=await r.json();
  if(d.state==="done"){
   if(d.verdict==="PASS"){card.textContent="✓";card.style.color="var(--g)";
    sub.textContent="verified — "+esc(d.event||"event")+" detected";why.textContent="";
    if(d.proof){render(d.proof);}}
   else{card.textContent="✗";card.style.color="var(--r)";
    sub.textContent="not verified";why.textContent=d.reason||"verification failed";}
   return;}
  if(d.state==="unknown"){card.textContent="?";card.style.color="var(--dim)";
   sub.textContent="unknown or expired session";why.textContent="";return;}
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
