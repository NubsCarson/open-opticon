// he-consent — the credible-sensors Track-6 mechanisms as a CLI.
//
// Two operations a recording's stakeholders can use to keep it humane:
//
//	seal/reveal — k-of-n THRESHOLD reveal. A full record is sealed under a random
//	  key that is split into n shares; any k holders can reveal it, k-1 cannot
//	  (information-theoretic). Group agreement, enforced by math.
//
//	disclose/verify-disclosure — CONSENT-GATED single-window disclosure. One window
//	  of a logged predicate stream is revealed with a Merkle inclusion proof, so a
//	  verifier confirms that exact window belongs to the stream (under a root it
//	  independently trusts, e.g. a he-log signed checkpoint) WITHOUT seeing the
//	  other windows.
//
// The crypto lives in src/verifier/threshold.go (stdlib only); this is its CLI
// surface. HONEST SCOPE: these are mechanisms — share custody and key lifecycle
// are operational policy, not enforced here, and the joint-data conflicting-wishes
// problem is unsolved.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
)

const usage = "usage: he-consent <seal|reveal|disclose|verify-disclosure> [flags]"

// Per-subcommand usage — one source of truth, printed both on a missing-flag error
// and on `he-consent <sub> --help`.
const (
	usageSeal             = "usage: he-consent seal --in <file|-> --k K --n N --out-dir DIR"
	usageReveal           = "usage: he-consent reveal --sealed sealed.json --share f1 [--share f2 ...]"
	usageDisclose         = "usage: he-consent disclose --stream <file: one window per line> --index I"
	usageVerifyDisclosure = "usage: he-consent verify-disclosure --disclosure d.json --root <hex>"
)

// helpRequested prints usage and returns true if args asks for help (-h/--help/help),
// so `he-consent <sub> --help` shows that subcommand's flags instead of the custom
// parser's "flag --help needs a value" error. Called first thing in each run*.
func helpRequested(args []string, u string) bool {
	// Only the LEADING token (the `<sub> --help` gesture), not any later arg —
	// otherwise a flag VALUE of "help"/"-h"/"--help" (e.g. a session/witness name
	// or file path) would silently no-op the command with a success exit.
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
	case "seal":
		runSeal(os.Args[2:])
	case "reveal":
		runReveal(os.Args[2:])
	case "disclose":
		runDisclose(os.Args[2:])
	case "verify-disclosure":
		runVerifyDisclosure(os.Args[2:])
	default:
		cli.Die("unknown subcommand %q (want seal|reveal|disclose|verify-disclosure)", os.Args[1])
	}
}

// shareJSON / sealedJSON / disclosureJSON are this CLI's on-disk wire formats.
type shareJSON struct {
	X int    `json:"x"`
	Y string `json:"y"` // hex, big-endian field element
}
type sealedJSON struct {
	Ciphertext string `json:"ciphertext"` // hex (nonce||AES-GCM ct)
	K          int    `json:"k"`
	N          int    `json:"n"`
}
type disclosureJSON struct {
	Index int      `json:"index"`
	Size  int      `json:"size"`
	Entry string   `json:"entry"` // hex of the disclosed window bytes
	Proof []string `json:"proof"` // hex Merkle inclusion path
}

// flagMap parses --k v / --k=v / repeatable --share f; bare flags are unused here.
// Repeated keys accumulate into repeated[key].
func flagMap(args []string) (map[string]string, map[string][]string) {
	single := map[string]string{}
	repeated := map[string][]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 3 || a[:2] != "--" {
			cli.Die("unexpected argument %q", a)
		}
		k := a[2:]
		var v string
		if eq := indexEq(k); eq >= 0 {
			k, v = k[:eq], k[eq+1:]
		} else if i+1 < len(args) && !(len(args[i+1]) >= 2 && args[i+1][:2] == "--") {
			v = args[i+1]
			i++
		} else {
			cli.Die("flag --%s needs a value", k)
		}
		single[k] = v
		repeated[k] = append(repeated[k], v)
	}
	return single, repeated
}

func indexEq(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return i
		}
	}
	return -1
}

func readInput(path string) []byte {
	if path == "-" {
		b, err := os.ReadFile("/dev/stdin")
		if err != nil {
			cli.Die("reading stdin: %v", err)
		}
		return b
	}
	b, err := os.ReadFile(path)
	if err != nil {
		cli.Die("reading %s: %v", path, err)
	}
	return b
}

func mustInt(s, name string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		cli.Die("--%s must be an integer: %v", name, err)
	}
	return n
}

// seal: ThresholdSeal the input under a fresh key split k-of-n; write sealed.json
// + one share-<x>.json per holder into --out-dir.
func runSeal(args []string) {
	if helpRequested(args, usageSeal) {
		return
	}
	f, _ := flagMap(args)
	in, outDir := f["in"], f["out-dir"]
	if in == "" || outDir == "" || f["k"] == "" || f["n"] == "" {
		cli.Die(usageSeal)
	}
	sr, err := verifier.ThresholdSeal(readInput(in), mustInt(f["k"], "k"), mustInt(f["n"], "n"))
	if err != nil {
		cli.Die("seal: %v", err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		cli.Die("mkdir %s: %v", outDir, err)
	}
	writeJSON(outDir+"/sealed.json", sealedJSON{Ciphertext: hex.EncodeToString(sr.Ciphertext), K: sr.K, N: sr.N})
	for _, sh := range sr.Shares {
		writeJSON(fmt.Sprintf("%s/share-%d.json", outDir, sh.X), shareJSON{X: sh.X, Y: hex.EncodeToString(sh.Y)})
	}
	fmt.Printf("sealed %d-of-%d into %s (sealed.json + %d share files)\n", sr.K, sr.N, outDir, sr.N)
}

// reveal: ThresholdOpen using the provided shares (>= k); writes plaintext to
// stdout. Fewer than k shares is refused.
func runReveal(args []string) {
	if helpRequested(args, usageReveal) {
		return
	}
	f, rep := flagMap(args)
	if f["sealed"] == "" || len(rep["share"]) == 0 {
		cli.Die(usageReveal)
	}
	var sj sealedJSON
	readJSON(f["sealed"], &sj)
	ct, err := hex.DecodeString(sj.Ciphertext)
	if err != nil {
		cli.Die("bad ciphertext hex: %v", err)
	}
	shares := make([]verifier.Share, 0, len(rep["share"]))
	for _, p := range rep["share"] {
		var s shareJSON
		readJSON(p, &s)
		y, err := hex.DecodeString(s.Y)
		if err != nil {
			cli.Die("bad share Y hex in %s: %v", p, err)
		}
		shares = append(shares, verifier.Share{X: s.X, Y: y})
	}
	pt, err := verifier.ThresholdOpen(&verifier.SealedReveal{Ciphertext: ct, K: sj.K, N: sj.N}, shares)
	if err != nil {
		cli.Die("reveal: %v", err)
	}
	os.Stdout.Write(pt)
}

// disclose: build a Merkle log from the windows (one per line of --stream),
// disclose window --index with its inclusion proof + the tree root.
func runDisclose(args []string) {
	if helpRequested(args, usageDisclose) {
		return
	}
	f, _ := flagMap(args)
	if f["stream"] == "" || f["index"] == "" {
		cli.Die(usageDisclose)
	}
	log := buildLog(f["stream"])
	d, err := log.DiscloseWindow(mustInt(f["index"], "index"))
	if err != nil {
		cli.Die("disclose: %v", err)
	}
	root := log.Root()
	dj := disclosureJSON{Index: d.Index, Size: d.Size, Entry: hex.EncodeToString(d.Entry)}
	for _, n := range d.Proof {
		dj.Proof = append(dj.Proof, hex.EncodeToString(n[:]))
	}
	out, _ := json.MarshalIndent(struct {
		disclosureJSON
		Root string `json:"root"`
	}{dj, hex.EncodeToString(root[:])}, "", "  ")
	fmt.Println(string(out))
}

// verify-disclosure: confirm the disclosed window is included under the root the
// caller independently trusts (--root, e.g. from a he-log signed checkpoint).
func runVerifyDisclosure(args []string) {
	if helpRequested(args, usageVerifyDisclosure) {
		return
	}
	f, _ := flagMap(args)
	if f["disclosure"] == "" || f["root"] == "" {
		cli.Die(usageVerifyDisclosure)
	}
	var dj disclosureJSON
	readJSON(f["disclosure"], &dj)
	rootBytes, err := hex.DecodeString(f["root"])
	if err != nil || len(rootBytes) != 32 {
		cli.Die("--root must be 32 bytes hex")
	}
	entry, err := hex.DecodeString(dj.Entry)
	if err != nil {
		cli.Die("bad entry hex: %v", err)
	}
	proof := make([][32]byte, 0, len(dj.Proof))
	for _, h := range dj.Proof {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			cli.Die("bad proof node hex")
		}
		var n [32]byte
		copy(n[:], b)
		proof = append(proof, n)
	}
	var root [32]byte
	copy(root[:], rootBytes)
	d := &verifier.WindowDisclosure{Index: dj.Index, Size: dj.Size, Entry: entry, Proof: proof}
	if !verifier.VerifyWindowDisclosure(d, root) {
		cli.Die("%s  window %d is NOT included under the given root", cli.Fail(), dj.Index)
	}
	fmt.Printf("%s  window %d is included under the trusted root\n", cli.Pass(), dj.Index)
	fmt.Printf("  disclosed: %s\n", entry)
}

func buildLog(streamPath string) *verifier.MerkleLog {
	data := readInput(streamPath)
	log := &verifier.MerkleLog{}
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '\n' {
			if i > start {
				log.Add(data[start:i])
			}
			start = i + 1
		}
	}
	if len(log.Leaves) == 0 {
		cli.Die("stream has no windows")
	}
	return log
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		cli.Die("writing %s: %v", path, err)
	}
}

func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		cli.Die("reading %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		cli.Die("parsing %s: %v", path, err)
	}
}
