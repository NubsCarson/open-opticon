// he-log — operate the Honest Ear endorsement transparency log.
//
// The log is an append-only Merkle tree (RFC 6962) of endorsement entries
// (e.g. a device's pub_x||pub_y). The operator periodically signs a checkpoint
// (size + root); a verifier trusts an endorsement only with an inclusion proof
// under a signed checkpoint. Auditors gossip checkpoints + consistency proofs so
// the log cannot fork or rewrite history.
//
// Subcommand first, then flags (e.g. `he-log add --log L <entryHex>`):
//
//	he-log genkey                                    # P-256 log key: priv/pub
//	he-log add --log L <entryHex>                    # append, prints index
//	he-log root --log L                              # current size + root
//	he-log checkpoint --log L --key <privHex> --origin honest-ear.log/v1
//	he-log prove --log L --index N --key <privHex>   # signed inclusion proof bundle
//	he-log consistency --log L --index OLD           # RFC 9162 consistency proof OLD->now
//	he-log verify --proof <proof.json>               # check a proof bundle
//
// State is a JSON file: {"leaves":["<hex>", ...]}. Stdlib only.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
)

type logFile struct {
	Leaves []string `json:"leaves"`
}

// proofBundle is the self-contained artifact a verifier checks.
type proofBundle struct {
	Entry      string   `json:"entry"` // hex of the logged endorsement
	Index      int      `json:"index"`
	Proof      []string `json:"proof"`      // hex of each audit-path node
	Checkpoint string   `json:"checkpoint"` // signed checkpoint body (text)
	CheckSig   string   `json:"checkpoint_sig"`
	LogPubX    string   `json:"log_pub_x"`
	LogPubY    string   `json:"log_pub_y"`
}

// consistencyBundle proves the current tree is an append-only extension of an
// earlier tree of size old_size (RFC 9162 consistency proof). Auditors gossip
// these so the log cannot fork or rewrite history.
type consistencyBundle struct {
	OldSize int      `json:"old_size"`
	NewSize int      `json:"new_size"`
	OldRoot string   `json:"old_root"`
	NewRoot string   `json:"new_root"`
	Proof   []string `json:"proof"`
}

// cosignBundle is an independent witness's signature over a checkpoint body. A
// verifier requires a threshold of these (VerifyCheckpointWitnesses) so a single
// log operator cannot equivocate.
type cosignBundle struct {
	Witness string `json:"witness"`
	PubX    string `json:"witness_pub_x"`
	PubY    string `json:"witness_pub_y"`
	Sig     string `json:"cosignature"`
}

// witnessList is a repeatable --witness flag (name:pubXhex:pubYhex), the set of
// enrolled witnesses whose cosignatures count toward the threshold.
type witnessList []string

func (w *witnessList) String() string     { return strings.Join(*w, ",") }
func (w *witnessList) Set(v string) error { *w = append(*w, v); return nil }

func load(path string) *verifier.MerkleLog {
	l := &verifier.MerkleLog{}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return l
	}
	if err != nil {
		cli.Die("reading %s: %v", path, err)
	}
	var lf logFile
	if err := json.Unmarshal(raw, &lf); err != nil {
		cli.Die("parsing %s: %v", path, err)
	}
	for _, h := range lf.Leaves {
		b, err := hex.DecodeString(h)
		if err != nil {
			cli.Die("bad leaf hex in %s: %v", path, err)
		}
		l.Leaves = append(l.Leaves, b)
	}
	return l
}

func save(path string, l *verifier.MerkleLog) {
	lf := logFile{}
	for _, leaf := range l.Leaves {
		lf.Leaves = append(lf.Leaves, hex.EncodeToString(leaf))
	}
	raw, _ := json.MarshalIndent(lf, "", "  ")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		cli.Die("writing %s: %v", path, err)
	}
}

func loadKey(privHex string) *ecdsa.PrivateKey {
	d, err := hex.DecodeString(privHex)
	if err != nil {
		cli.Die("bad --key hex: %v", err)
	}
	k := new(ecdsa.PrivateKey)
	k.PublicKey.Curve = elliptic.P256()
	k.D = new(big.Int).SetBytes(d)
	k.PublicKey.X, k.PublicKey.Y = elliptic.P256().ScalarBaseMult(d)
	return k
}

func pad32(n *big.Int) []byte {
	b := make([]byte, 32)
	n.FillBytes(b)
	return b
}

const usage = `he-log — operate the Honest Ear endorsement transparency log (append-only RFC 6962).

usage: he-log <command> [flags]

commands (subcommand first, then flags):
  genkey                                            P-256 log key: prints priv/pub
  add --log L <entryHex>                             append an entry, prints its index
  root --log L                                       current log size + Merkle root
  checkpoint --log L --key <privHex> [--origin O]    sign a (size, root) checkpoint
  prove --log L --index N --key <privHex>            signed inclusion-proof bundle
  consistency --log L --index OLD                    RFC 9162 consistency proof OLD->now
  cosign --checkpoint <body> --key <privHex> --witness NAME   witness-cosign a checkpoint
  cosign-verify --checkpoint <body> --cosigs <c.json> --enrolled name:x:y --witness-threshold k
  verify --proof <proof.json>                        check an inclusion-proof bundle

State is a JSON file (--log, default he-log.json). Stdlib only.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Println(usage)
		return
	}
	logPath := flag.String("log", "he-log.json", "log state file")
	keyHex := flag.String("key", "", "log P-256 private key (hex), for checkpoint")
	origin := flag.String("origin", "honest-ear.log/v1", "checkpoint origin line")
	index := flag.Int("index", 0, "leaf index, for prove")
	proofPath := flag.String("proof", "", "proof bundle JSON, for verify")
	cpPath := flag.String("checkpoint", "", "checkpoint body file, for cosign")
	witness := flag.String("witness", "", "witness name, for cosign")
	cosigsPath := flag.String("cosigs", "", "cosignatures JSON array, for cosign-verify")
	threshold := flag.Int("witness-threshold", 1, "min enrolled witness cosigs, for cosign-verify")
	var enrolledWitnesses witnessList
	flag.Var(&enrolledWitnesses, "enrolled", "enrolled witness as name:pubXhex:pubYhex (repeatable, for cosign-verify)")
	flag.CommandLine.Parse(os.Args[2:]) // subcommand-first; flags follow it

	switch cmd {
	case "genkey":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			cli.Die("%v", err)
		}
		fmt.Printf("priv : %x\n", pad32(k.D))
		fmt.Printf("pub_x: %x\n", pad32(k.PublicKey.X))
		fmt.Printf("pub_y: %x\n", pad32(k.PublicKey.Y))

	case "add":
		entry, err := hex.DecodeString(flag.Arg(0))
		if err != nil {
			cli.Die("entry must be hex (usage: he-log add --log L <entryHex>): %v", err)
		}
		l := load(*logPath)
		i := l.Add(entry)
		save(*logPath, l)
		fmt.Printf("added at index %d (size now %d)\n", i, l.Size())

	case "root":
		l := load(*logPath)
		r := l.Root()
		fmt.Printf("size : %d\nroot : %x\n", l.Size(), r[:])

	case "checkpoint":
		if *keyHex == "" {
			cli.Die("checkpoint needs --key <privHex>")
		}
		l := load(*logPath)
		key := loadKey(*keyHex)
		root := l.Root()
		sig, err := verifier.SignCheckpoint(*origin, l.Size(), root, key)
		if err != nil {
			cli.Die("%v", err)
		}
		fmt.Printf("%s", verifier.CheckpointBody(*origin, l.Size(), root))
		fmt.Printf("sig  : %x\n", sig)
		fmt.Printf("log_pub_x: %x\nlog_pub_y: %x\n", pad32(key.PublicKey.X), pad32(key.PublicKey.Y))

	case "prove":
		if *keyHex == "" {
			cli.Die("prove needs --key <privHex> to sign the checkpoint it proves against")
		}
		l := load(*logPath)
		proof, err := l.InclusionProof(*index)
		if err != nil {
			cli.Die("%v", err)
		}
		key := loadKey(*keyHex)
		root := l.Root()
		sig, err := verifier.SignCheckpoint(*origin, l.Size(), root, key)
		if err != nil {
			cli.Die("%v", err)
		}
		pb := proofBundle{
			Entry:      hex.EncodeToString(l.Leaves[*index]),
			Index:      *index,
			Checkpoint: string(verifier.CheckpointBody(*origin, l.Size(), root)),
			CheckSig:   hex.EncodeToString(sig),
			LogPubX:    hex.EncodeToString(pad32(key.PublicKey.X)),
			LogPubY:    hex.EncodeToString(pad32(key.PublicKey.Y)),
		}
		for _, node := range proof {
			pb.Proof = append(pb.Proof, hex.EncodeToString(node[:]))
		}
		out, _ := json.MarshalIndent(pb, "", "  ")
		fmt.Println(string(out))

	case "consistency":
		l := load(*logPath)
		oldSize := *index
		proof, err := l.ConsistencyProof(oldSize)
		if err != nil {
			cli.Die("%v", err)
		}
		oldRoot := (&verifier.MerkleLog{Leaves: l.Leaves[:oldSize]}).Root()
		newRoot := l.Root()
		cb := consistencyBundle{
			OldSize: oldSize, NewSize: l.Size(),
			OldRoot: hex.EncodeToString(oldRoot[:]),
			NewRoot: hex.EncodeToString(newRoot[:]),
		}
		for _, node := range proof {
			cb.Proof = append(cb.Proof, hex.EncodeToString(node[:]))
		}
		out, _ := json.MarshalIndent(cb, "", "  ")
		fmt.Println(string(out))

	case "cosign":
		if *keyHex == "" || *cpPath == "" || *witness == "" {
			cli.Die("cosign needs --checkpoint <body> --key <witnessPrivHex> --witness NAME")
		}
		body, err := os.ReadFile(*cpPath)
		if err != nil {
			cli.Die("reading checkpoint: %v", err)
		}
		if _, _, _, err := verifier.ParseCheckpoint(body); err != nil {
			cli.Die("not a valid checkpoint body: %v", err)
		}
		key := loadKey(*keyHex)
		sig, err := verifier.CosignCheckpoint(body, key)
		if err != nil {
			cli.Die("%v", err)
		}
		cb := cosignBundle{
			Witness: *witness,
			PubX:    hex.EncodeToString(pad32(key.PublicKey.X)),
			PubY:    hex.EncodeToString(pad32(key.PublicKey.Y)),
			Sig:     hex.EncodeToString(sig),
		}
		out, _ := json.MarshalIndent(cb, "", "  ")
		fmt.Println(string(out))

	case "cosign-verify":
		if *cpPath == "" || *cosigsPath == "" {
			cli.Die("cosign-verify needs --checkpoint <body> --cosigs <cosigs.json> --enrolled name:x:y [...] [--witness-threshold k]")
		}
		body, err := os.ReadFile(*cpPath)
		if err != nil {
			cli.Die("reading checkpoint: %v", err)
		}
		if _, _, _, err := verifier.ParseCheckpoint(body); err != nil {
			cli.Die("not a valid checkpoint body: %v", err)
		}
		raw, err := os.ReadFile(*cosigsPath)
		if err != nil {
			cli.Die("reading cosigs: %v", err)
		}
		var cbs []cosignBundle
		if err := json.Unmarshal(raw, &cbs); err != nil {
			cli.Die("parsing cosigs: %v", err)
		}
		var cosigs []verifier.Cosignature
		for _, cb := range cbs {
			cosigs = append(cosigs, verifier.Cosignature{
				Witness: cb.Witness,
				PubX:    mustHex(cb.PubX, "witness pub_x"),
				PubY:    mustHex(cb.PubY, "witness pub_y"),
				Sig:     mustHex(cb.Sig, "cosignature"),
			})
		}
		enrolled := make([]verifier.Prover, 0, len(enrolledWitnesses))
		for _, spec := range enrolledWitnesses {
			parts := strings.Split(spec, ":")
			if len(parts) != 3 {
				cli.Die("--enrolled must be name:pubXhex:pubYhex, got %q", spec)
			}
			enrolled = append(enrolled, verifier.Prover{
				Name: parts[0],
				PubX: mustHex(parts[1], "enrolled pub_x"),
				PubY: mustHex(parts[2], "enrolled pub_y"),
			})
		}
		ok := verifier.VerifyCheckpointWitnesses(body, cosigs, enrolled)
		if len(ok) >= *threshold {
			fmt.Printf("%s  %d-of-%d enrolled witnesses cosigned: %s\n",
				cli.Pass(), len(ok), *threshold, strings.Join(ok, ", "))
		} else {
			fmt.Printf("%s  only %d enrolled witness cosignature(s), need %d\n",
				cli.Fail(), len(ok), *threshold)
			os.Exit(1)
		}

	case "verify":
		if *proofPath == "" {
			cli.Die("verify needs --proof <proof.json>")
		}
		raw, err := os.ReadFile(*proofPath)
		if err != nil {
			cli.Die("reading proof: %v", err)
		}
		var pb proofBundle
		if err := json.Unmarshal(raw, &pb); err != nil {
			cli.Die("parsing proof: %v", err)
		}
		entry := mustHex(pb.Entry, "entry")
		var proof [][32]byte
		for _, h := range pb.Proof {
			var node [32]byte
			copy(node[:], mustHex(h, "proof node"))
			proof = append(proof, node)
		}
		err = verifier.CheckLoggedEndorsement(entry, pb.Index, proof,
			[]byte(pb.Checkpoint), mustHex(pb.CheckSig, "sig"),
			mustHex(pb.LogPubX, "log_pub_x"), mustHex(pb.LogPubY, "log_pub_y"))
		if err != nil {
			fmt.Printf("%s  %v\n", cli.Fail(), err)
			os.Exit(1)
		}
		fmt.Printf("%s  endorsement is in the signed, append-only log (index %d)\n", cli.Pass(), pb.Index)

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", cmd, usage)
		os.Exit(2)
	}
}

func mustHex(s, what string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		cli.Die("bad %s hex: %v", what, err)
	}
	return b
}
