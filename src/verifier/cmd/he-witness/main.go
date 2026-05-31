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
//	    --log-pub-x <hex> --log-pub-y <hex> [--origin O] [--state f.json] [--poll 15]
//	      -> daemon: polls every --poll seconds; serves GET /cosignature and /health.
//
// The witness PINS the log's public key (--log-pub-x/--log-pub-y): a checkpoint
// is only considered if its signature verifies under that pinned key. Stdlib-only.
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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

func main() {
	if len(os.Args) < 2 {
		cli.Die("usage: he-witness <check|serve> [flags]")
	}
	switch os.Args[1] {
	case "check":
		runCheck(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	default:
		cli.Die("unknown subcommand %q (want check|serve)", os.Args[1])
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

func parseCommon(fs []string, extra func(addFlag)) config {
	// Minimal hand-rolled flag parse so both subcommands share the set without a
	// second flag.FlagSet ceremony. Accepts --k v and --k=v.
	m := map[string]string{}
	for i := 0; i < len(fs); i++ {
		a := fs[i]
		if len(a) < 2 || a[:2] != "--" {
			cli.Die("unexpected argument %q", a)
		}
		k := a[2:]
		if eq := indexByte(k, '='); eq >= 0 {
			m[k[:eq]] = k[eq+1:]
			continue
		}
		if i+1 >= len(fs) {
			cli.Die("flag --%s needs a value", k)
		}
		m[k] = fs[i+1]
		i++
	}
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

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func runCheck(args []string) {
	cfg := parseCommon(args, nil)
	st := loadState(cfg.statePath)
	res, err := poll(http.DefaultClient, cfg.logURL, cfg.origin, cfg.logPubX, cfg.logPubY, cfg.key, cfg.name, st)
	if err != nil {
		cli.Die("poll: %v", err)
	}
	if !res.Accepted {
		fmt.Fprintf(os.Stderr, "%s  REFUSED to cosign: %s\n", cli.Fail(), res.Reason)
		os.Exit(1)
	}
	saveState(cfg.statePath, st)
	c := res.Cosignature
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"witness":       c.Witness,
		"witness_pub_x": hex.EncodeToString(c.PubX),
		"witness_pub_y": hex.EncodeToString(c.PubY),
		"cosignature":   hex.EncodeToString(c.Sig),
	})
}

func runServe(args []string) {
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

	d := &daemon{cfg: cfg, st: loadState(cfg.statePath)}
	d.once() // poll immediately so /cosignature is populated before first tick
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			d.once()
		}
	}()

	http.HandleFunc("/cosignature", d.handleCosignature)
	http.HandleFunc("/health", d.handleHealth)
	fmt.Fprintf(os.Stderr, "he-witness %q: polling %s every %s, serving %s\n",
		cfg.name, cfg.logURL, interval, addr)
	cli.Die("server exited: %v", http.ListenAndServe(addr, nil))
}

type daemon struct {
	cfg      config
	mu       sync.Mutex
	st       *witnessState
	latest   *pollResult
	lastErr  string
	healthOK bool
}

func (d *daemon) once() {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := poll(http.DefaultClient, d.cfg.logURL, d.cfg.origin, d.cfg.logPubX, d.cfg.logPubY, d.cfg.key, d.cfg.name, d.st)
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
		saveState(d.cfg.statePath, d.st)
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

func (d *daemon) handleHealth(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	code := 200
	if !d.healthOK {
		code = 503
	}
	cli.WriteJSON(w, code, map[string]any{
		"witness":    d.cfg.name,
		"ok":         d.healthOK,
		"size":       d.st.Size,
		"root":       d.st.Root,
		"last_error": d.lastErr,
	})
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

func loadState(path string) *witnessState {
	st := &witnessState{}
	if path == "" {
		return st
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return st // first run: empty baseline
	}
	_ = json.Unmarshal(raw, st)
	return st
}

func saveState(path string, st *witnessState) {
	if path == "" {
		return
	}
	raw, _ := json.MarshalIndent(st, "", "  ")
	_ = os.WriteFile(path, raw, 0o600)
}
