// he-logd — a minimal HTTP server for a transparency log, so independent
// witnesses (he-witness) can poll its signed checkpoints and consistency proofs
// over the network and cosign them. It is the "log operator" surface: it reads
// the same append-only log file `he-log` uses ({"leaves":[hex,...]}), signs the
// current checkpoint with the log key, and answers consistency-proof requests.
//
//	he-logd --addr :8088 --log L.json --key <privHex> [--origin honest-ear.log/v1]
//
// Endpoints (read-only):
//
//	GET /checkpoint            -> {origin,size,root,body,sig,log_pub_x,log_pub_y}
//	GET /consistency?from=N    -> {from,new_size,new_root,proof:[hex,...]}
//
// The log file is re-read per request, so appends made by `he-log add` are served
// live. Stdlib-only.
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
)

func main() {
	addr := flag.String("addr", ":8088", "listen address")
	logPath := flag.String("log", "", "path to the append-only log file ({\"leaves\":[hex,...]}) — required")
	keyHex := flag.String("key", "", "log signing key (32-byte P-256 scalar, hex) — required")
	origin := flag.String("origin", "honest-ear.log/v1", "checkpoint origin line")
	flag.Parse()

	if *logPath == "" || *keyHex == "" {
		cli.Die("--log and --key are required")
	}
	key, err := verifier.PrivKeyFromHex(*keyHex)
	if err != nil {
		cli.Die("bad --key: %v", err)
	}

	loadLog := func() (*verifier.MerkleLog, error) { return loadLogFile(*logPath) }
	http.HandleFunc("/checkpoint", checkpointHandler(loadLog, *origin, key))
	http.HandleFunc("/consistency", consistencyHandler(loadLog))

	fmt.Fprintf(os.Stderr, "he-logd: serving %s on %s (origin %q)\n", *logPath, *addr, *origin)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

// loadFunc loads the current log (re-read per request so appends are served live).
type loadFunc = func() (*verifier.MerkleLog, error)

// checkpointHandler serves the log's current signed checkpoint.
func checkpointHandler(load loadFunc, origin string, key *ecdsa.PrivateKey) http.HandlerFunc {
	px, py := verifier.PubXY(key)
	return func(w http.ResponseWriter, _ *http.Request) {
		l, err := load()
		if err != nil {
			cli.WriteJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		root := l.Root()
		body := verifier.CheckpointBody(origin, l.Size(), root)
		sig, err := verifier.SignCheckpoint(origin, l.Size(), root, key)
		if err != nil {
			cli.WriteJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		cli.WriteJSON(w, 200, map[string]any{
			"origin":    origin,
			"size":      l.Size(),
			"root":      hex.EncodeToString(root[:]),
			"body":      string(body),
			"sig":       hex.EncodeToString(sig),
			"log_pub_x": hex.EncodeToString(px),
			"log_pub_y": hex.EncodeToString(py),
		})
	}
}

// consistencyHandler serves an RFC 9162 consistency proof from ?from to current.
func consistencyHandler(load loadFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		from, err := strconv.Atoi(r.URL.Query().Get("from"))
		if err != nil || from < 0 {
			cli.WriteJSON(w, 400, map[string]string{"error": "bad ?from"})
			return
		}
		l, err := load()
		if err != nil {
			cli.WriteJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if from > l.Size() {
			cli.WriteJSON(w, 400, map[string]string{"error": "from exceeds current size"})
			return
		}
		proof, err := l.ConsistencyProof(from)
		if err != nil {
			cli.WriteJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		root := l.Root()
		ph := make([]string, len(proof))
		for i, n := range proof {
			ph[i] = hex.EncodeToString(n[:])
		}
		cli.WriteJSON(w, 200, map[string]any{
			"from":     from,
			"new_size": l.Size(),
			"new_root": hex.EncodeToString(root[:]),
			"proof":    ph,
		})
	}
}

// loadLogFile reads the {"leaves":[hex,...]} log file and rebuilds the MerkleLog.
func loadLogFile(path string) (*verifier.MerkleLog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Leaves []string `json:"leaves"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing log file: %w", err)
	}
	l := &verifier.MerkleLog{}
	for i, h := range f.Leaves {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("leaf %d: %w", i, err)
		}
		l.Add(b)
	}
	return l, nil
}
