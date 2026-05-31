// he-gui — a clean, end-user web UI for open-opticon.
//
// Tap the mic, it listens in short windows, and for each window it runs the
// real detect -> sign -> verify pipeline and shows a plain-language verified
// result. The browser only sends downsampled PCM to this local server; the
// server runs the same he-attest-sim the tests use (detect + sign with the
// published test key), then verifies the bound output. Nothing leaves the box.
//
//	he-gui [--addr :8095] [--sim sim/bin/he-attest-sim]
package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync/atomic"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
)

//go:embed index.html
var indexHTML []byte

var counter uint64 // monotonic, for the anti-replay gate

type result struct {
	Verified bool   `json:"verified"`
	Event    string `json:"event"`
	Presence bool   `json:"presence"`
	Voice    bool   `json:"voice"`
	Reason   string `json:"reason"`
	Counter  uint64 `json:"counter"`
	// Full bound-output bundle, so the browser can run the live "tamper test"
	// against /verify (flip a byte → watch the verifier reject it).
	Nonce   string `json:"nonce"`
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
	PubX    string `json:"pub_x"`
	PubY    string `json:"pub_y"`
}

// verifyReq is a client-supplied bundle (the /verify "tamper test") plus the
// nonce to check it against.
type verifyReq struct {
	Nonce string `json:"nonce"`
	verifier.Bundle
}

func main() {
	addr := flag.String("addr", ":8095", "listen address")
	sim := flag.String("sim", "sim/bin/he-attest-sim", "path to he-attest-sim binary")
	flag.Parse()

	if _, err := os.Stat(*sim); err != nil {
		log.Fatalf("he-attest-sim not found at %q (build it: make -C sim, or pass --sim): %v", *sim, err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})

	http.HandleFunc("/listen", listenHandler(*sim))
	http.HandleFunc("/verify", verifyHandler)

	log.Printf("open-opticon web UI on http://localhost%s  (sim: %s)", *addr, *sim)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

// listenHandler validates the request, then runs the detect->sign->verify
// pipeline. Input-validation early-returns happen before any exec, so they are
// unit-testable without the sim binary.
func listenHandler(sim string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST raw s16le 16kHz mono PCM", http.StatusMethodNotAllowed)
			return
		}
		pcm, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil || len(pcm) < 64 {
			cli.WriteJSON(w, http.StatusOK, result{Reason: "no audio"})
			return
		}
		if len(pcm)%2 != 0 {
			cli.WriteJSON(w, http.StatusOK, result{Reason: "PCM must be 16-bit samples (even byte count)"})
			return
		}
		cli.WriteJSON(w, http.StatusOK, process(sim, pcm))
	}
}

// process writes the PCM to a temp file, runs he-attest-sim with a fresh nonce,
// then verifies the bound output — the same path the e2e test exercises.
func process(sim string, pcm []byte) result {
	tmp, err := os.CreateTemp("", "he-*.pcm")
	if err != nil {
		return result{Reason: "temp: " + err.Error()}
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(pcm); err != nil {
		tmp.Close()
		return result{Reason: "write: " + err.Error()}
	}
	tmp.Close()

	nb := make([]byte, 32)
	_, _ = rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	ctr := atomic.AddUint64(&counter, 1)

	out, err := exec.Command(sim, tmp.Name(), nonce, fmt.Sprint(ctr)).Output()
	if err != nil {
		return result{Reason: "sim: " + err.Error()}
	}
	var b verifier.Bundle // extra sim fields (event/presence/...) are ignored on purpose
	if err := json.Unmarshal(out, &b); err != nil {
		return result{Reason: "parse: " + err.Error()}
	}

	v := verifier.VerifyBundle(b, verifier.Options{ExpectedNonce: nb, LastCounter: ctr - 1})

	res := result{
		Verified: v.OK,
		Reason:   v.Reason,
		Counter:  ctr,
		Nonce:    nonce,
		Payload:  b.Payload,
		Sig:      b.Sig,
		PubX:     b.PubX,
		PubY:     b.PubY,
	}
	// Display the VERIFIED predicate, not the untrusted sim stdout.
	fillVerified(&res, v)
	return res
}

// verifyHandler re-verifies a client-supplied bundle (the "tamper test"): the
// browser flips a byte or swaps the nonce and watches the verifier reject it.
// Stateless and signature-only — no sim, no detection — so it's safe and fast.
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST a bound-output bundle", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var q verifyReq
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		cli.WriteJSON(w, http.StatusOK, result{Reason: "bad bundle: " + err.Error()})
		return
	}
	nb, err := hex.DecodeString(q.Nonce)
	if err != nil {
		cli.WriteJSON(w, http.StatusOK, result{Reason: "bad nonce hex"})
		return
	}
	v := verifier.VerifyBundle(q.Bundle, verifier.Options{ExpectedNonce: nb, LastCounter: 0})
	res := result{Verified: v.OK, Reason: v.Reason}
	fillVerified(&res, v)
	cli.WriteJSON(w, http.StatusOK, res)
}

// fillVerified copies the verified predicate into res — only on success, so an
// unverified result never shows a confident classification.
func fillVerified(res *result, v verifier.VerifyResult) {
	if v.OK && v.Predicate != nil {
		res.Event = v.Predicate.EventName()
		res.Presence = v.Predicate.Presence == 1
		res.Voice = v.Predicate.VoiceActive
	}
}
