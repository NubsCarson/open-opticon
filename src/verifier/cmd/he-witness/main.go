// he-witness — an independent transparency-log witness.
//
// A witness polls a log operator's signed checkpoints (he-logd), verifies that
// each new checkpoint is a CONSISTENT append-only extension of the last one it
// saw (RFC 9162 consistency proof), and cosigns ONLY consistent checkpoints. If
// the log ever presents a forked or rewound history, the witness refuses to
// cosign — so a single operator cannot equivocate without detection. This is the
// operational half of the witness-cosigning protocol whose crypto lives in
// transparency.go (CosignCheckpoint / VerifyCheckpointWitnesses).
//
//	he-witness check --name w1 --key <privHex> --log-url URL \
//	    --log-pub-x <hex> --log-pub-y <hex> [--origin O] [--state f.json]
//	      -> one poll: prints a cosignature JSON on accept, or "REFUSED" + exit 1.
//
//	he-witness serve --addr :9101 --name w1 --key <privHex> --log-url URL \
//	    --log-pub-x <hex> --log-pub-y <hex> [--origin O] [--state f.json] [--poll 15] \
//	    [--peer name,url,pubXhex,pubYhex ...]
//	      -> daemon: polls every --poll seconds; serves GET /cosignature and /health.
//	         With --peer (repeatable), it ALSO continuously cross-checks each pinned
//	         peer witness and reports equivocation in /health (anti-equivocation mesh
//	         of explicit pinned peers; no discovery).
//
//	he-witness compare --peer-url URL --peer-name w2 \
//	    --peer-pub-x <hex> --peer-pub-y <hex> --state f.json \
//	    [--origin O] [--log-url URL]
//	      -> one-shot anti-equivocation cross-check: fetch a PEER witness's published
//	         cosignature, verify it under the peer's PINNED key, and compare its
//	         checkpoint to our own view. Same size + divergent root across two
//	         independently-keyed witnesses = the log equivocated -> exit 1.
//
// The witness PINS the log's public key (--log-pub-x/--log-pub-y): a checkpoint
// is only considered if its signature verifies under that pinned key. Stdlib-only.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
)

// witnessState is the witness's persisted view of the log's latest accepted
// checkpoint. "Root == empty" means the witness has never seen a checkpoint yet
// (first sight is the trust baseline).
type witnessState struct {
	Origin string `json:"origin"`
	Size   int    `json:"size"`
	Root   string `json:"root"` // hex of the 32-byte root
}

type checkpointResp struct {
	Body    string `json:"body"`
	Sig     string `json:"sig"`
	LogPubX string `json:"log_pub_x"`
	LogPubY string `json:"log_pub_y"`
}

type consistencyResp struct {
	NewSize int      `json:"new_size"`
	NewRoot string   `json:"new_root"`
	Proof   []string `json:"proof"`
}

type pollResult struct {
	Accepted    bool
	Reason      string // why refused (or "consistent extension" / "first sight")
	Body        []byte // checkpoint body cosigned (when accepted)
	Cosignature verifier.Cosignature
}

const usage = "usage: he-witness <check|serve|compare|verify-equivocation> [flags]"

// Per-subcommand usage, printed on `he-witness <sub> --help`.
const (
	usageCheck       = "usage: he-witness check --name N --key <privHex> --log-url URL --log-pub-x X --log-pub-y Y [--origin O] [--state f]"
	usageServe       = "usage: he-witness serve --name N --key <privHex> --log-url URL --log-pub-x X --log-pub-y Y [--origin O] [--state f] [--addr :9101] [--poll secs] [--peer name,url,pubXhex,pubYhex ...]"
	usageCompare     = "usage: he-witness compare --peer-url URL --peer-name N --peer-pub-x X --peer-pub-y Y [--origin O] [--state f]"
	usageVerifyEquiv = "usage: he-witness verify-equivocation --file proof.json --a-pub-x X --a-pub-y Y --b-pub-x X --b-pub-y Y"
)

// helpRequested prints usage and returns true if args asks for help (-h/--help/help),
// so `he-witness <sub> --help` shows that subcommand's flags instead of the parser's
// "flag --help needs a value" error.
func helpRequested(args []string, u string) bool {
	// Only the LEADING token (the `<sub> --help` gesture), not any later arg —
	// otherwise a flag VALUE of "help"/"-h"/"--help" (e.g. a --name/--origin) would
	// silently no-op the command with a success exit.
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fmt.Println(u)
		return true
	}
	return false
}

func main() {
	if len(os.Args) < 2 {
		cli.Die(usage)
	}
	switch os.Args[1] {
	case "-h", "--help", "help":
		fmt.Println(usage)
	case "check":
		runCheck(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "compare":
		runCompare(os.Args[2:])
	case "verify-equivocation":
		runVerifyEquivocation(os.Args[2:])
	default:
		cli.Die("unknown subcommand %q (want check|serve|compare|verify-equivocation)", os.Args[1])
	}
}

// config holds the parsed common flags + the witness key.
type config struct {
	name             string
	origin           string
	logURL           string
	statePath        string
	key              *ecdsa.PrivateKey
	logPubX, logPubY []byte
}

// flagMap parses --k v / --k=v into a map; the minimal shared parser for every
// he-witness subcommand (no flag.FlagSet ceremony, no duplicate-purpose copies).
func flagMap(fs []string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(fs); i++ {
		a := fs[i]
		if len(a) < 2 || a[:2] != "--" {
			cli.Die("unexpected argument %q", a)
		}
		k := a[2:]
		if eq := strings.IndexByte(k, '='); eq >= 0 {
			m[k[:eq]] = k[eq+1:]
			continue
		}
		if i+1 >= len(fs) {
			cli.Die("flag --%s needs a value", k)
		}
		m[k] = fs[i+1]
		i++
	}
	return m
}

func parseCommon(fs []string, extra func(addFlag)) config {
	m := flagMap(fs)
	need := func(k string) string {
		v, ok := m[k]
		if !ok || v == "" {
			cli.Die("--%s is required", k)
		}
		return v
	}
	if extra != nil {
		extra(func(k string) string { return m[k] })
	}
	key, err := verifier.PrivKeyFromHex(need("key"))
	if err != nil {
		cli.Die("bad --key: %v", err)
	}
	lx, err := hex.DecodeString(need("log-pub-x"))
	if err != nil {
		cli.Die("bad --log-pub-x: %v", err)
	}
	ly, err := hex.DecodeString(need("log-pub-y"))
	if err != nil {
		cli.Die("bad --log-pub-y: %v", err)
	}
	origin := m["origin"]
	if origin == "" {
		origin = "honest-ear.log/v1"
	}
	return config{
		name:      need("name"),
		origin:    origin,
		logURL:    need("log-url"),
		statePath: m["state"],
		key:       key,
		logPubX:   lx,
		logPubY:   ly,
	}
}

type addFlag = func(string) string

func runCheck(args []string) {
	if helpRequested(args, usageCheck) {
		return
	}
	cfg := parseCommon(args, nil)
	st, err := loadState(cfg.statePath)
	if err != nil {
		cli.Die("%v", err)
	}
	res, err := poll(cli.HTTPClient(), cfg.logURL, cfg.origin, cfg.logPubX, cfg.logPubY, cfg.key, cfg.name, st)
	if err != nil {
		cli.Die("poll: %v", err)
	}
	if !res.Accepted {
		fmt.Fprintf(os.Stderr, "%s  REFUSED to cosign: %s\n", cli.Fail(), res.Reason)
		os.Exit(1)
	}
	if err := saveState(cfg.statePath, st); err != nil {
		cli.Die("save state: %v", err)
	}
	c := res.Cosignature
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"witness":       c.Witness,
		"witness_pub_x": hex.EncodeToString(c.PubX),
		"witness_pub_y": hex.EncodeToString(c.PubY),
		"cosignature":   hex.EncodeToString(c.Sig),
	})
}

// peer is a pinned peer witness the serve daemon continuously cross-checks.
type peer struct {
	name, url  string
	pubX, pubY []byte
}

// parsePeers scans args for repeated `--peer name,url,pubXhex,pubYhex` specs (the
// peer's key is PINNED — discovery/trust-on-first-use is deliberately out of scope,
// since the anti-equivocation guarantee depends on independent pinned keys).
func parsePeers(args []string) []peer {
	var specs []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--peer" && i+1 < len(args) {
			specs = append(specs, args[i+1])
			i++
		} else if strings.HasPrefix(args[i], "--peer=") {
			specs = append(specs, args[i][len("--peer="):])
		}
	}
	var peers []peer
	seen := map[string]bool{}
	for _, s := range specs {
		f := strings.Split(s, ",")
		if len(f) != 4 {
			cli.Die("--peer must be name,url,pubXhex,pubYhex (got %q)", s)
		}
		if f[0] == "" {
			cli.Die("--peer name must not be empty")
		}
		if seen[f[0]] { // distinct names so each peer gets its own /health entry
			cli.Die("duplicate --peer name %q", f[0])
		}
		seen[f[0]] = true
		px, err := hex.DecodeString(f[2])
		if err != nil {
			cli.Die("bad peer %q pub_x: %v", f[0], err)
		}
		py, err := hex.DecodeString(f[3])
		if err != nil {
			cli.Die("bad peer %q pub_y: %v", f[0], err)
		}
		peers = append(peers, peer{name: f[0], url: strings.TrimRight(f[1], "/"), pubX: px, pubY: py})
	}
	return peers
}

// crossVerdict is the outcome of a witness-to-witness cross-check.
type crossVerdict int

const (
	crossAgree        crossVerdict = iota // peer's view is consistent with ours
	crossEquivocation                     // divergent root / non-extension: the log equivocated
	crossInconclusive                     // no baseline to judge against (be honest, not a false PASS)
)

// peerCosigResp mirrors what handleCosignature publishes.
type peerCosigResp struct {
	Witness        string `json:"witness"`
	WitnessPubX    string `json:"witness_pub_x"`
	WitnessPubY    string `json:"witness_pub_y"`
	Cosignature    string `json:"cosignature"`
	CheckpointBody string `json:"checkpoint_body"`
}

const equivProofSchema = "honest-ear/equivocation-proof/v1"

// equivCkpt is one cosigned checkpoint inside an equivProof.
type equivCkpt struct {
	Witness        string `json:"witness"`
	CheckpointBody string `json:"checkpoint_body"`
	Cosignature    string `json:"cosignature"`
	WitnessPubX    string `json:"witness_pub_x"`
	WitnessPubY    string `json:"witness_pub_y"`
}

// equivProof is TRANSFERABLE evidence the log equivocated: two checkpoints at the
// same size with different roots, each cosigned by a distinct pinned witness (our
// own cosigned view + a divergent peer's). Served at /equivocation-proof and
// checked — by anyone, trusting only the two PINNED witness keys, not the producer
// — via verifier.VerifyEquivocation / `he-witness verify-equivocation`.
type equivProof struct {
	Schema string    `json:"schema"`
	A      equivCkpt `json:"a"`
	B      equivCkpt `json:"b"`
}

// crossCheck is the pure decision: does a peer witness's checkpoint (already
// sig-verified under the peer's pinned key and origin-checked) agree with our
// view? peerProof is the log's consistency proof when the peer is ahead (nil if
// not fetched). It writes nothing and reuses VerifyConsistency for the ahead case.
func crossCheck(hasView bool, ourSize int, ourRoot [32]byte, peerSize int, peerRoot [32]byte, peerProof [][32]byte) (crossVerdict, string) {
	if !hasView {
		return crossInconclusive, "no local view yet — nothing to compare against"
	}
	switch {
	case peerSize == ourSize:
		if peerRoot == ourRoot {
			return crossAgree, fmt.Sprintf("peer agrees at size %d", ourSize)
		}
		return crossEquivocation, fmt.Sprintf(
			"EQUIVOCATION: same size %d but peer root %x… != our root %x…", ourSize, peerRoot[:4], ourRoot[:4])
	case peerSize > ourSize:
		if peerProof == nil {
			return crossInconclusive, fmt.Sprintf(
				"peer is ahead (size %d > %d) — pass --log-url to fetch a proof the extension is consistent", peerSize, ourSize)
		}
		if verifier.VerifyConsistency(ourSize, peerSize, peerProof, ourRoot, peerRoot) {
			return crossAgree, fmt.Sprintf("peer is a consistent append-only extension (size %d extends %d)", peerSize, ourSize)
		}
		return crossEquivocation, fmt.Sprintf(
			"EQUIVOCATION: peer size %d is NOT an append-only extension of our %d", peerSize, ourSize)
	default: // peerSize < ourSize
		return crossInconclusive, fmt.Sprintf(
			"we are ahead (our size %d > peer %d) — cannot judge without a proof our tree extends the peer's", ourSize, peerSize)
	}
}

// runCompare: one-shot anti-equivocation cross-check against a peer witness. Read
// only — it never cosigns or writes state.
func runCompare(args []string) {
	if helpRequested(args, usageCompare) {
		return
	}
	m := flagMap(args)
	need := func(k string) string {
		v, ok := m[k]
		if !ok || v == "" {
			cli.Die("--%s is required", k)
		}
		return v
	}
	origin := m["origin"]
	if origin == "" {
		origin = "honest-ear.log/v1"
	}
	peerURL := strings.TrimRight(need("peer-url"), "/")
	peerName := need("peer-name")
	px, err := hex.DecodeString(need("peer-pub-x"))
	if err != nil {
		cli.Die("bad --peer-pub-x: %v", err)
	}
	py, err := hex.DecodeString(need("peer-pub-y"))
	if err != nil {
		cli.Die("bad --peer-pub-y: %v", err)
	}
	st, err := loadState(m["state"])
	if err != nil {
		cli.Die("%v", err)
	}
	client := cli.HTTPClient()

	var pr peerCosigResp
	if err := getJSON(client, peerURL+"/cosignature", &pr); err != nil {
		cli.Die("fetch peer cosignature: %v", err)
	}
	if pr.Witness != peerName {
		cli.Die("peer name mismatch: got %q, expected %q", pr.Witness, peerName)
	}
	body := []byte(pr.CheckpointBody)
	sig, err := hex.DecodeString(pr.Cosignature)
	if err != nil {
		cli.Die("bad peer cosignature hex: %v", err)
	}
	// Pin the peer key: verify under the PINNED key, never the key the peer
	// self-reports (else a malicious peer signs with a fresh key and reports it).
	if !verifier.VerifyCheckpointSig(body, sig, px, py) {
		cli.Die("%s  peer cosignature does not verify under the pinned peer key", cli.Fail())
	}
	porg, psize, proot, err := verifier.ParseCheckpoint(body)
	if err != nil {
		cli.Die("parse peer checkpoint: %v", err)
	}
	if porg != origin {
		cli.Die("%s  peer origin mismatch (got %q, want %q)", cli.Fail(), porg, origin)
	}

	hasView := st.Root != ""
	var ourRoot [32]byte
	if hasView {
		if ourRoot, err = hexRoot(st.Root); err != nil {
			cli.Die("bad persisted root: %v", err)
		}
	}
	// If the peer is ahead and we were given the log, fetch the consistency proof
	// that ties the peer's root to ours.
	var peerProof [][32]byte
	if hasView && psize > st.Size && m["log-url"] != "" {
		var cr consistencyResp
		if err := getJSON(client, fmt.Sprintf("%s/consistency?from=%d", strings.TrimRight(m["log-url"], "/"), st.Size), &cr); err != nil {
			cli.Die("fetch consistency proof: %v", err)
		}
		if peerProof, err = decodeProof(cr.Proof); err != nil {
			cli.Die("bad consistency proof: %v", err)
		}
	}

	verdict, reason := crossCheck(hasView, st.Size, ourRoot, psize, proot, peerProof)
	switch verdict {
	case crossAgree:
		fmt.Printf("%s  peer %q: %s\n", cli.Pass(), peerName, reason)
	case crossEquivocation:
		fmt.Printf("%s  peer %q: %s\n", cli.Fail(), peerName, reason)
		os.Exit(1)
	default:
		fmt.Printf("INCONCLUSIVE  peer %q: %s\n", peerName, reason)
		os.Exit(2)
	}
}

// runVerifyEquivocation checks a transferable equivocation proof OFFLINE: it
// verifies each checkpoint's cosignature under the witness key the caller PINS via
// flags (NOT the self-reported key in the file), then confirms same-origin/size,
// different-root. So anyone — not just the witness that produced it — can confirm
// the log equivocated, trusting only the two pinned keys.
func runVerifyEquivocation(args []string) {
	if helpRequested(args, usageVerifyEquiv) {
		return
	}
	m := flagMap(args)
	need := func(k string) string {
		v, ok := m[k]
		if !ok || v == "" {
			cli.Die("--%s is required", k)
		}
		return v
	}
	raw, err := os.ReadFile(need("file"))
	if err != nil {
		cli.Die("read proof: %v", err)
	}
	var p equivProof
	if err := json.Unmarshal(raw, &p); err != nil {
		cli.Die("parse proof JSON: %v", err)
	}
	hx := func(k string) []byte {
		b, err := hex.DecodeString(need(k))
		if err != nil {
			cli.Die("bad --%s hex: %v", k, err)
		}
		return b
	}
	aX, aY, bX, bY := hx("a-pub-x"), hx("a-pub-y"), hx("b-pub-x"), hx("b-pub-y")
	cosigA, err := hex.DecodeString(p.A.Cosignature)
	if err != nil {
		cli.Die("bad checkpoint A cosignature hex: %v", err)
	}
	cosigB, err := hex.DecodeString(p.B.Cosignature)
	if err != nil {
		cli.Die("bad checkpoint B cosignature hex: %v", err)
	}
	ok, reason := verifier.VerifyEquivocation(
		[]byte(p.A.CheckpointBody), cosigA, aX, aY,
		[]byte(p.B.CheckpointBody), cosigB, bX, bY)
	if !ok {
		cli.Die("%s  not a valid equivocation proof: %s", cli.Fail(), reason)
	}
	fmt.Printf("%s  %s\n", cli.Pass(), reason)
	fmt.Printf("  witness A: %s\n  witness B: %s\n", p.A.Witness, p.B.Witness)
}

func runServe(args []string) {
	if helpRequested(args, usageServe) {
		return
	}
	var addr, pollSecs string
	cfg := parseCommon(args, func(get addFlag) {
		addr = get("addr")
		pollSecs = get("poll")
	})
	if addr == "" {
		addr = ":9101"
	}
	interval := 15 * time.Second
	if pollSecs != "" {
		if n, err := time.ParseDuration(pollSecs + "s"); err == nil {
			interval = n
		}
	}

	st, err := loadState(cfg.statePath)
	if err != nil {
		cli.Die("%v", err)
	}
	d := &daemon{cfg: cfg, client: cli.HTTPClient(), peers: parsePeers(args), st: st}
	d.once()           // poll immediately so /cosignature is populated before first tick
	d.checkPeers()     // and cross-check pinned peers before serving /health
	d.pullPeerProofs() // pull-based anti-entropy: catch up on a fork we missed while down
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			d.once()
			d.checkPeers()
			d.pullPeerProofs()
		}
	}()

	http.HandleFunc("/cosignature", d.handleCosignature)
	http.HandleFunc("/health", d.handleHealth)
	http.HandleFunc("/equivocation-proof", d.handleEquivocationProof)
	http.HandleFunc("/equivocation-intake", d.handleEquivocationIntake)
	fmt.Fprintf(os.Stderr, "he-witness %q: polling %s every %s, cross-checking %d peer(s), serving %s\n",
		cfg.name, cfg.logURL, interval, len(d.peers), addr)
	cli.Die("server exited: %v", cli.Serve(addr))
}

type daemon struct {
	cfg      config
	client   *http.Client
	peers    []peer
	mu       sync.Mutex
	st       *witnessState
	latest   *pollResult
	lastErr  string
	healthOK bool
	// peerStatus[name] = "agree" | "equivocation: ..." | "inconclusive: ..." | an
	// error; equivocation is true if any peer's view diverged from ours.
	peerStatus   map[string]string
	equivocation bool
	// proof is the transferable same-size split-view evidence (our cosigned view +
	// the first divergent peer's), assembled once on detection; served at
	// /equivocation-proof. nil until a same-size equivocation is seen.
	proof *equivProof
}

// checkPeers cross-checks each pinned peer's published cosignature against our own
// view (reusing crossCheck). A detected equivocation — two independently-keyed
// witnesses holding divergent roots at the same size — means the log equivocated;
// we record it and mark unhealthy so a downstream quorum stops trusting this log.
// Network I/O happens WITHOUT the lock; results are written under it.
func (d *daemon) checkPeers() {
	if len(d.peers) == 0 {
		return
	}
	d.mu.Lock()
	hasView := d.st.Root != ""
	ourSize := d.st.Size
	ourRootHex := d.st.Root
	client := d.client
	d.mu.Unlock()
	if client == nil {
		client = cli.HTTPClient()
	}
	var ourRoot [32]byte
	if hasView {
		ourRoot, _ = hexRoot(ourRootHex) // loadState validated it
	}

	status := make(map[string]string, len(d.peers))
	anyEquiv := false
	var proofPeer *equivCkpt // the first same-size divergent peer -> B side of the proof
	for _, p := range d.peers {
		var pr peerCosigResp
		if err := getJSON(client, p.url+"/cosignature", &pr); err != nil {
			status[p.name] = "unreachable: " + err.Error()
			continue
		}
		body := []byte(pr.CheckpointBody)
		sig, err := hex.DecodeString(pr.Cosignature)
		if err != nil {
			status[p.name] = "bad cosignature hex"
			continue
		}
		if !verifier.VerifyCheckpointSig(body, sig, p.pubX, p.pubY) {
			status[p.name] = "cosignature not under pinned key"
			continue
		}
		porg, psize, proot, err := verifier.ParseCheckpoint(body)
		if err != nil || porg != d.cfg.origin {
			status[p.name] = "checkpoint parse/origin mismatch"
			continue
		}
		var peerProof [][32]byte
		if hasView && psize > ourSize {
			var cr consistencyResp
			if getJSON(client, fmt.Sprintf("%s/consistency?from=%d", d.cfg.logURL, ourSize), &cr) == nil {
				peerProof, _ = decodeProof(cr.Proof)
			}
		}
		v, reason := crossCheck(hasView, ourSize, ourRoot, psize, proot, peerProof)
		switch v {
		case crossAgree:
			status[p.name] = "agree: " + reason
		case crossEquivocation:
			status[p.name] = "EQUIVOCATION: " + reason
			anyEquiv = true
			// Capture the first SAME-SIZE divergent peer as the B side of a
			// transferable proof (the different-size / inconsistent-extension case
			// needs a failing consistency proof, not a two-checkpoint pair).
			if proofPeer == nil && psize == ourSize {
				proofPeer = &equivCkpt{
					Witness:        p.name,
					CheckpointBody: pr.CheckpointBody,
					Cosignature:    pr.Cosignature,
					WitnessPubX:    hex.EncodeToString(p.pubX),
					WitnessPubY:    hex.EncodeToString(p.pubY),
				}
			}
		default:
			status[p.name] = "inconclusive: " + reason
		}
	}

	d.mu.Lock()
	d.peerStatus = status
	if anyEquiv {
		d.equivocation = true // latch: once an equivocation is seen, stay alarmed
		d.healthOK = false
	}
	// Assemble the transferable proof once, from our own cosigned view (A) + the
	// divergent peer (B). Needs d.latest (our cosignature over OUR root at this size).
	var fresh *equivProof
	if proofPeer != nil && d.proof == nil && d.latest != nil {
		c := d.latest.Cosignature
		d.proof = &equivProof{
			Schema: equivProofSchema,
			A: equivCkpt{
				Witness:        c.Witness,
				CheckpointBody: string(d.latest.Body),
				Cosignature:    hex.EncodeToString(c.Sig),
				WitnessPubX:    hex.EncodeToString(c.PubX),
				WitnessPubY:    hex.EncodeToString(c.PubY),
			},
			B: *proofPeer,
		}
		fresh = d.proof
	}
	d.mu.Unlock()

	// One-hop relay (best-effort, OUTSIDE the lock): push the just-assembled proof to
	// each pinned peer's intake so a peer that hasn't yet seen the split latches too.
	// Strictly within the pinned set; no transitive re-flood (that is frontier).
	if fresh != nil {
		body, _ := json.Marshal(fresh)
		for _, p := range d.peers {
			pushProof(client, p.url+"/equivocation-intake", body)
		}
	}
}

func (d *daemon) once() {
	d.mu.Lock()
	defer d.mu.Unlock()
	client := d.client
	if client == nil {
		client = cli.HTTPClient()
	}
	res, err := poll(client, d.cfg.logURL, d.cfg.origin, d.cfg.logPubX, d.cfg.logPubY, d.cfg.key, d.cfg.name, d.st)
	if err != nil {
		d.lastErr = err.Error()
		d.healthOK = false
		return
	}
	d.lastErr = ""
	if res.Accepted {
		r := res
		d.latest = &r
		d.healthOK = true
		if err := saveState(d.cfg.statePath, d.st); err != nil {
			d.lastErr = "state save failed: " + err.Error()
			d.healthOK = false // persistence failure is operationally significant
		}
	} else {
		// A detected inconsistency is NOT healthy — surface it, keep the last good cosig.
		d.lastErr = "REFUSED: " + res.Reason
		d.healthOK = false
	}
}

func (d *daemon) handleCosignature(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.latest == nil {
		cli.WriteJSON(w, 503, map[string]string{"error": "no consistent checkpoint cosigned yet"})
		return
	}
	c := d.latest.Cosignature
	cli.WriteJSON(w, 200, map[string]any{
		"witness":         c.Witness,
		"witness_pub_x":   hex.EncodeToString(c.PubX),
		"witness_pub_y":   hex.EncodeToString(c.PubY),
		"cosignature":     hex.EncodeToString(c.Sig),
		"checkpoint_body": string(d.latest.Body),
	})
}

// handleEquivocationProof serves the transferable split-view proof once one is
// detected (404 until then). Anyone can fetch it and verify it offline under the
// two pinned witness keys via `he-witness verify-equivocation`.
func (d *daemon) handleEquivocationProof(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.proof == nil {
		cli.WriteJSON(w, 404, map[string]string{"error": "no equivocation detected"})
		return
	}
	cli.WriteJSON(w, 200, d.proof)
}

// pinnedKey resolves a witness NAME to the key we PINNED for it — self (cfg.key) or
// a --peer. cfg.name/cfg.key and d.peers are set once at startup and never mutated,
// so no lock is needed. ok=false means we never pinned that witness (can't trust it).
func (d *daemon) pinnedKey(name string) (x, y []byte, ok bool) {
	if name == d.cfg.name {
		px, py := verifier.PubXY(d.cfg.key)
		return px, py, true
	}
	for _, p := range d.peers {
		if p.name == name {
			return p.pubX, p.pubY, true
		}
	}
	return nil, nil, false
}

// handleEquivocationIntake adopts an equivocation proof POSTed by a pinned peer
// (one-hop relay). It is SELF-AUTHENTICATING: it verifies each half under OUR pinned
// key for that witness name (never the self-reported key), so a bogus POST can't make
// us falsely latch — only a proof that genuinely verifies under keys we already trust
// is adopted. This propagates a detected fork to a witness that pinned the two
// witnesses but had not yet cross-checked the divergence itself. It does NOT re-flood
// onward (epidemic gossip is frontier, see docs/DESIGN_WITNESS_GOSSIP.md).
func (d *daemon) handleEquivocationIntake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		cli.WriteJSON(w, 405, map[string]string{"error": "POST a proof"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var p equivProof
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		cli.WriteJSON(w, 400, map[string]string{"error": "bad proof: " + err.Error()})
		return
	}
	if ok, reason := d.tryAdopt(&p); ok {
		cli.WriteJSON(w, 200, map[string]string{"adopted": reason})
	} else {
		cli.WriteJSON(w, 400, map[string]string{"error": reason})
	}
}

// tryAdopt is the shared verify+adopt path for an equivocation proof, reached BOTH
// from the push intake (handleEquivocationIntake) and the pull anti-entropy
// (pullPeerProofs). It verifies each half under OUR pinned key for that witness name
// (NEVER the self-reported key), scopes the proof to the log we watch, and on success
// latches the (monotonic, permanent) equivocation alarm. On the FIRST adoption it also
// re-pushes to our pinned peers (transitive flood). Returns (false, reason) on any
// rejection so callers can surface or ignore it.
func (d *daemon) tryAdopt(p *equivProof) (bool, string) {
	aX, aY, okA := d.pinnedKey(p.A.Witness)
	bX, bY, okB := d.pinnedKey(p.B.Witness)
	if !okA || !okB {
		return false, "proof names a witness we have not pinned; cannot verify"
	}
	cosigA, err1 := hex.DecodeString(p.A.Cosignature)
	cosigB, err2 := hex.DecodeString(p.B.Cosignature)
	if err1 != nil || err2 != nil {
		return false, "bad cosignature hex"
	}
	ok, reason := verifier.VerifyEquivocation(
		[]byte(p.A.CheckpointBody), cosigA, aX, aY,
		[]byte(p.B.CheckpointBody), cosigB, bX, bY)
	if !ok {
		return false, "proof does not verify under our pinned keys: " + reason
	}
	// Scope to the log WE watch (mirroring poll + checkPeers): VerifyEquivocation only
	// proves the two halves share SOME common origin, so without this a genuine
	// equivocation of a DIFFERENT log (if pinned peers reuse keys across logs) would
	// falsely latch us. Both halves share an origin, so checking A alone suffices.
	if porg, _, _, perr := verifier.ParseCheckpoint([]byte(p.A.CheckpointBody)); perr != nil || porg != d.cfg.origin {
		return false, "proof origin is not the log we watch"
	}
	d.mu.Lock()
	first := d.proof == nil // first time we've seen this fork -> re-push it onward
	if first {
		d.proof = p
	}
	d.equivocation = true // a verified proof latches us, however it arrived
	d.healthOK = false
	client := d.client
	d.mu.Unlock()

	// Transitive flooding (best-effort, OUTSIDE the lock): on FIRST adoption, re-push to
	// our pinned peers. The d.proof latch is the seen-set, so every node re-pushes AT
	// MOST ONCE — the flood terminates (O(edges), no loop). The single slot means a node
	// propagates only the FIRST distinct fork it adopts; the 503 alarm above is
	// unconditional + permanent, so the safety verdict is unaffected. Together with
	// pullPeerProofs (pull-based anti-entropy) a node also catches up on a fork it missed
	// while offline. Eclipse resistance + discovery stay frontier
	// (docs/DESIGN_WITNESS_GOSSIP.md).
	if first {
		if client == nil {
			client = cli.HTTPClient()
		}
		body, _ := json.Marshal(p)
		for _, peer := range d.peers {
			pushProof(client, peer.url+"/equivocation-intake", body)
		}
	}
	return true, reason
}

// pullPeerProofs is pull-based anti-entropy: if we hold NO proof yet, GET each pinned
// peer's /equivocation-proof and adopt the first valid one (verified under OUR pinned
// keys via tryAdopt). This catches a witness up on a fork it missed while offline or
// transiently unreachable during the best-effort push flood. The whole replicated
// state is a single proof, so a per-tick pull is COMPLETE reconciliation — not a
// sketch of real large-state anti-entropy.
func (d *daemon) pullPeerProofs() {
	d.mu.Lock()
	have := d.proof != nil
	client := d.client
	d.mu.Unlock()
	if have || len(d.peers) == 0 {
		return
	}
	if client == nil {
		client = cli.HTTPClient()
	}
	for _, p := range d.peers {
		var pr equivProof
		if err := getJSON(client, p.url+"/equivocation-proof", &pr); err != nil {
			continue // 404 (peer has none) or unreachable -> skip
		}
		if ok, _ := d.tryAdopt(&pr); ok {
			return // adopted (and re-pushed onward by tryAdopt)
		}
	}
}

// pushProof POSTs a freshly-assembled proof to a pinned peer's intake (best-effort,
// one-hop; errors ignored — relay is opportunistic, not a delivery guarantee).
func pushProof(client *http.Client, url string, body []byte) {
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err == nil {
		_ = resp.Body.Close()
	}
}

func (d *daemon) handleHealth(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	code := 200
	if !d.healthOK {
		code = 503
	}
	out := map[string]any{
		"witness":    d.cfg.name,
		"ok":         d.healthOK,
		"size":       d.st.Size,
		"root":       d.st.Root,
		"last_error": d.lastErr,
	}
	if len(d.peers) > 0 {
		out["peers"] = d.peerStatus
		out["equivocation_detected"] = d.equivocation
	}
	cli.WriteJSON(w, code, out)
}

// poll fetches the current checkpoint, pins+verifies the log signature, checks
// consistency against st, and (on accept) advances st and returns a cosignature.
// A detected fork/rewind returns Accepted=false with a reason (not an error);
// transport/parse failures return an error.
func poll(client *http.Client, base, origin string, logPubX, logPubY []byte,
	key *ecdsa.PrivateKey, name string, st *witnessState) (pollResult, error) {
	var cp checkpointResp
	if err := getJSON(client, base+"/checkpoint", &cp); err != nil {
		return pollResult{}, fmt.Errorf("fetch checkpoint: %w", err)
	}
	body := []byte(cp.Body)
	sig, err := hex.DecodeString(cp.Sig)
	if err != nil {
		return pollResult{}, fmt.Errorf("bad checkpoint sig hex: %w", err)
	}
	// Pin the log key: the checkpoint must be signed by the operator we trust.
	if !verifier.VerifyCheckpointSig(body, sig, logPubX, logPubY) {
		return pollResult{Accepted: false, Reason: "checkpoint signature does not verify under the pinned log key"}, nil
	}
	org, size, root, err := verifier.ParseCheckpoint(body)
	if err != nil {
		return pollResult{}, fmt.Errorf("parse checkpoint: %w", err)
	}
	if org != origin {
		return pollResult{Accepted: false, Reason: fmt.Sprintf("origin mismatch (got %q, want %q)", org, origin)}, nil
	}

	// Consistency decision relative to the witness's last accepted view.
	if st.Root == "" { // first sight: trust baseline
		advance(st, origin, size, root)
		return accept(body, key, name, "first sight (baseline)"), nil
	}
	oldRoot, err := hexRoot(st.Root)
	if err != nil {
		return pollResult{}, fmt.Errorf("bad persisted root: %w", err)
	}
	switch {
	case size < st.Size:
		return pollResult{Accepted: false, Reason: fmt.Sprintf("log rewound: size %d < last seen %d", size, st.Size)}, nil
	case size == st.Size:
		if root != oldRoot {
			return pollResult{Accepted: false, Reason: "fork: same size, different root than last seen"}, nil
		}
		return accept(body, key, name, "unchanged checkpoint"), nil
	default: // size > st.Size — need a consistency proof
		var cr consistencyResp
		if err := getJSON(client, fmt.Sprintf("%s/consistency?from=%d", base, st.Size), &cr); err != nil {
			return pollResult{}, fmt.Errorf("fetch consistency proof: %w", err)
		}
		proof, err := decodeProof(cr.Proof)
		if err != nil {
			return pollResult{}, fmt.Errorf("bad consistency proof: %w", err)
		}
		if !verifier.VerifyConsistency(st.Size, size, proof, oldRoot, root) {
			return pollResult{Accepted: false, Reason: fmt.Sprintf("inconsistent: size %d is not an append-only extension of %d", size, st.Size)}, nil
		}
		advance(st, origin, size, root)
		return accept(body, key, name, "consistent extension"), nil
	}
}

func accept(body []byte, key *ecdsa.PrivateKey, name, reason string) pollResult {
	sig, err := verifier.CosignCheckpoint(body, key)
	if err != nil {
		return pollResult{Accepted: false, Reason: "cosign error: " + err.Error()}
	}
	px, py := verifier.PubXY(key)
	return pollResult{
		Accepted: true,
		Reason:   reason,
		Body:     body,
		Cosignature: verifier.Cosignature{
			Witness: name, PubX: px, PubY: py, Sig: sig,
		},
	}
}

func advance(st *witnessState, origin string, size int, root [32]byte) {
	st.Origin = origin
	st.Size = size
	st.Root = hex.EncodeToString(root[:])
}

func hexRoot(h string) ([32]byte, error) {
	var r [32]byte
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return r, errors.New("root must be 32 bytes hex")
	}
	copy(r[:], b)
	return r, nil
}

func decodeProof(hexes []string) ([][32]byte, error) {
	out := make([][32]byte, len(hexes))
	for i, h := range hexes {
		r, err := hexRoot(h)
		if err != nil {
			return nil, err
		}
		out[i] = r
	}
	return out, nil
}

func getJSON(client *http.Client, url string, v any) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(raw))
	}
	return json.Unmarshal(raw, v)
}

// loadState reads the persisted witness view. A MISSING file is the honest
// first-run baseline; a PRESENT-but-corrupt file (bad JSON, or a malformed root)
// is an error, not a silent reset to baseline — re-trusting first-sight after
// state corruption could let a fork slip past, so the operator must see it.
func loadState(path string) (*witnessState, error) {
	st := &witnessState{}
	if path == "" {
		return st, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil // first run: baseline
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, fmt.Errorf("corrupt witness state %s: %w", path, err)
	}
	if st.Root != "" {
		if _, err := hexRoot(st.Root); err != nil {
			return nil, fmt.Errorf("invalid root in state %s: %w", path, err)
		}
	}
	return st, nil
}

func saveState(path string, st *witnessState) error {
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}
