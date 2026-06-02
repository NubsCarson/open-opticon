package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	verifier "honest-ear/verifier"
)

// fakeLog is an in-process he-logd: it serves /checkpoint and /consistency from a
// swappable MerkleLog so a test can grow it or fork it between polls.
type fakeLog struct {
	mu     sync.Mutex
	log    *verifier.MerkleLog
	key    *ecdsa.PrivateKey
	origin string
}

func (f *fakeLog) set(l *verifier.MerkleLog) {
	f.mu.Lock()
	f.log = l
	f.mu.Unlock()
}

func (f *fakeLog) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/checkpoint", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		root := f.log.Root()
		body := verifier.CheckpointBody(f.origin, f.log.Size(), root)
		sig, _ := verifier.SignCheckpoint(f.origin, f.log.Size(), root, f.key)
		px, py := verifier.PubXY(f.key)
		writeJSON(w, map[string]any{
			"body": string(body), "sig": hex.EncodeToString(sig),
			"log_pub_x": hex.EncodeToString(px), "log_pub_y": hex.EncodeToString(py),
		})
	})
	mux.HandleFunc("/consistency", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		from, _ := strconv.Atoi(r.URL.Query().Get("from"))
		proof, err := f.log.ConsistencyProof(from)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		root := f.log.Root()
		ph := make([]string, len(proof))
		for i, n := range proof {
			ph[i] = hex.EncodeToString(n[:])
		}
		writeJSON(w, map[string]any{"new_size": f.log.Size(), "new_root": hex.EncodeToString(root[:]), "proof": ph})
	})
	return httptest.NewServer(mux)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func logOf(entries ...string) *verifier.MerkleLog {
	l := &verifier.MerkleLog{}
	for _, e := range entries {
		l.Add([]byte(e))
	}
	return l
}

func TestWitnessAcceptsConsistentExtensionRefusesFork(t *testing.T) {
	logKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wx, wy := verifier.PubXY(wKey)
	enrolled := []verifier.Prover{{Name: "w1", PubX: wx, PubY: wy}}
	logX, logY := verifier.PubXY(logKey)

	fl := &fakeLog{log: logOf("a", "b", "c"), key: logKey, origin: "honest-ear.log/v1"}
	srv := fl.server()
	defer srv.Close()

	st := &witnessState{}
	doPoll := func() (pollResult, error) {
		return poll(srv.Client(), srv.URL, "honest-ear.log/v1", logX, logY, wKey, "w1", st)
	}

	// 1. First sight (size 3): accepted; the cosignature must validate as an
	//    enrolled witness over the exact checkpoint body.
	res, err := doPoll()
	if err != nil {
		t.Fatalf("poll1: %v", err)
	}
	if !res.Accepted {
		t.Fatalf("first sight refused: %s", res.Reason)
	}
	names := verifier.VerifyCheckpointWitnesses(res.Body, []verifier.Cosignature{res.Cosignature}, enrolled)
	if len(names) != 1 || names[0] != "w1" {
		t.Fatalf("cosignature did not validate as enrolled witness: %v", names)
	}
	if st.Size != 3 {
		t.Fatalf("state size = %d, want 3", st.Size)
	}

	// 2. Consistent append (size 5): accepted, state advances.
	fl.set(logOf("a", "b", "c", "d", "e"))
	res, err = doPoll()
	if err != nil {
		t.Fatalf("poll2: %v", err)
	}
	if !res.Accepted {
		t.Fatalf("consistent extension refused: %s", res.Reason)
	}
	if st.Size != 5 {
		t.Fatalf("state size = %d, want 5", st.Size)
	}

	// 3. FORK: a different history at the same size (a,b,c,d,X) — not an extension
	//    of what the witness cosigned. Must be refused; state unchanged.
	fl.set(logOf("a", "b", "c", "d", "X"))
	prev := *st
	res, err = doPoll()
	if err != nil {
		t.Fatalf("poll3 transport: %v", err)
	}
	if res.Accepted {
		t.Fatal("FORK accepted; witness must refuse to cosign a divergent history")
	}
	if *st != prev {
		t.Fatalf("state advanced on a refused fork: %+v", *st)
	}

	// 4. REWIND: a shorter log than last seen. Must be refused.
	fl.set(logOf("a", "b"))
	res, _ = doPoll()
	if res.Accepted {
		t.Fatal("REWIND accepted; witness must refuse a shrunk log")
	}
}

func TestWitnessRefusesWrongLogKey(t *testing.T) {
	logKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fl := &fakeLog{log: logOf("a", "b"), key: logKey, origin: "honest-ear.log/v1"}
	srv := fl.server()
	defer srv.Close()

	// Pin a DIFFERENT log key than the one signing checkpoints.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ox, oy := verifier.PubXY(other)
	st := &witnessState{}
	res, err := poll(srv.Client(), srv.URL, "honest-ear.log/v1", ox, oy, wKey, "w1", st)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if res.Accepted {
		t.Fatal("accepted a checkpoint not signed by the pinned log key")
	}
}

// crossCheck is the anti-equivocation decision used by `he-witness compare`:
// given our view and a peer witness's (already sig-verified) checkpoint, does the
// peer agree, equivocate, or is it inconclusive? Pure — no HTTP, no state writes.
func TestCrossCheck(t *testing.T) {
	ours := logOf("a", "b", "c") // our view: size 3
	ourRoot := ours.Root()

	// No local baseline -> inconclusive (never a false PASS).
	if v, _ := crossCheck(false, 0, [32]byte{}, 3, ourRoot, nil); v != crossInconclusive {
		t.Errorf("no-view: got %v, want inconclusive", v)
	}

	// Same size, same root -> agree.
	if v, _ := crossCheck(true, 3, ourRoot, 3, ourRoot, nil); v != crossAgree {
		t.Errorf("same root: got %v, want agree", v)
	}

	// Same size, DIVERGENT root -> equivocation (the whole point: two independently
	// keyed witnesses holding different roots at the same size means the log forked).
	forkAt3 := logOf("a", "b", "X").Root()
	if v, _ := crossCheck(true, 3, ourRoot, 3, forkAt3, nil); v != crossEquivocation {
		t.Errorf("divergent root: got %v, want equivocation", v)
	}

	// Peer ahead with a valid consistency proof that our tree extends to theirs -> agree.
	peer := logOf("a", "b", "c", "d", "e") // size 5, genuinely extends ours
	proof, err := peer.ConsistencyProof(3)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := crossCheck(true, 3, ourRoot, 5, peer.Root(), proof); v != crossAgree {
		t.Errorf("consistent extension: got %v, want agree", v)
	}

	// Peer ahead but NO proof supplied -> inconclusive (don't guess).
	if v, _ := crossCheck(true, 3, ourRoot, 5, peer.Root(), nil); v != crossInconclusive {
		t.Errorf("ahead no-proof: got %v, want inconclusive", v)
	}

	// Peer ahead but its tree is a FORK (differs before our size): its own
	// consistency proof can't tie back to our root -> equivocation.
	fork := logOf("a", "b", "Z", "d", "e") // diverges at leaf index 2
	fProof, err := fork.ConsistencyProof(3)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := crossCheck(true, 3, ourRoot, 5, fork.Root(), fProof); v != crossEquivocation {
		t.Errorf("forked extension: got %v, want equivocation", v)
	}

	// We are ahead of the peer -> inconclusive (this slice doesn't prove the reverse direction).
	if v, _ := crossCheck(true, 5, peer.Root(), 3, ourRoot, nil); v != crossInconclusive {
		t.Errorf("peer behind: got %v, want inconclusive", v)
	}
}
