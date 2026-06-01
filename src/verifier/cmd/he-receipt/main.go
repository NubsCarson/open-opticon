// he-receipt — emit and verify "restraint receipts": a portable proof that a
// local-first app (e.g. VoxTerm transcription) processed an input window and
// emitted only a derived artifact (text), retaining no raw input — signed by a
// hardware-backed P-256 key and hash-chained per session so a dropped batch is a
// detectable gap. Receipts are transparency-log leaves (feed them to he-log /
// he-logd), so a session's stream is append-only, witness-cosignable, and
// on-chain-anchorable with the existing machinery. The verifier is root-agnostic
// (OP-TEE/CAAM on Arm, Secure Enclave on Apple, TPM on PC).
//
//	he-receipt emit  --session S --batch N --audio <file> --text <file|-> \
//	                 --key <privHex> [--prev <hex>] [--retained]
//	      -> prints a signed receipt bundle JSON; its digest (the next prev) on stderr.
//	he-receipt verify [--expect-prev <hex>] [--pin-x <hex> --pin-y <hex>]
//	                 [--require-not-retained] [receipt.json]
//	      -> PASS/FAIL + fields + next_digest.
//
// HONEST SCOPE: a receipt is a signed, tamper-evident, gap-free binding of
// input->output under a hardware key — accountability, not a hardware
// confidentiality proof. "Which code ran / no covert exfil" still needs firmware
// measurement (a TEE) and/or reproducible builds + open source.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
)

func main() {
	if len(os.Args) < 2 {
		cli.Die("usage: he-receipt <emit|verify> [flags]")
	}
	switch os.Args[1] {
	case "emit":
		runEmit(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	default:
		cli.Die("unknown subcommand %q (want emit|verify)", os.Args[1])
	}
}

// flags parses --k v / --k=v and bare --flag (value "1"); minimal, shared.
func flags(args []string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[:2] != "--" {
			cli.Die("unexpected argument %q", a)
		}
		k := a[2:]
		if eq := indexByte(k, '='); eq >= 0 {
			m[k[:eq]] = k[eq+1:]
			continue
		}
		// bare boolean flags
		if k == "retained" || k == "require-not-retained" {
			m[k] = "1"
			continue
		}
		if i+1 >= len(args) {
			cli.Die("flag --%s needs a value", k)
		}
		m[k] = args[i+1]
		i++
	}
	return m
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func sha256File(path string) []byte {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		cli.Die("reading %s: %v", path, err)
	}
	h := sha256.Sum256(raw)
	// We hash and DROP the bytes here — the tool never stores or forwards them.
	return h[:]
}

func runEmit(args []string) {
	m := flags(args)
	need := func(k string) string {
		if m[k] == "" {
			cli.Die("--%s is required", k)
		}
		return m[k]
	}
	key, err := verifier.PrivKeyFromHex(need("key"))
	if err != nil {
		cli.Die("bad --key: %v", err)
	}
	batch, err := strconv.ParseUint(need("batch"), 10, 64)
	if err != nil {
		cli.Die("bad --batch: %v", err)
	}
	prev := make([]byte, 32) // genesis default
	if m["prev"] != "" {
		if prev, err = hex.DecodeString(m["prev"]); err != nil || len(prev) != 32 {
			cli.Die("--prev must be 32 bytes hex")
		}
	}
	px, py := verifier.PubXY(key)
	r := verifier.Receipt{
		Origin:     verifier.ReceiptOrigin,
		Session:    need("session"),
		Batch:      batch,
		InputHash:  sha256File(need("audio")), // hashed, then discarded
		OutputHash: sha256File(need("text")),
		Retained:   m["retained"] == "1",
		PrevDigest: prev,
	}
	body := verifier.ReceiptBody(r)
	sig, err := verifier.SignNote(body, key)
	if err != nil {
		cli.Die("sign: %v", err)
	}
	out, _ := json.MarshalIndent(verifier.ReceiptBundle{
		Schema: verifier.ReceiptOrigin,
		Body:   string(body),
		Sig:    hex.EncodeToString(sig),
		PubX:   hex.EncodeToString(px),
		PubY:   hex.EncodeToString(py),
	}, "", "  ")
	fmt.Println(string(out))
	// The digest is the next receipt's --prev and this receipt's transparency-log leaf.
	fmt.Fprintf(os.Stderr, "digest %s\n", hex.EncodeToString(verifier.ReceiptDigest(body)))
}

func runVerify(args []string) {
	m := flags(args)
	var raw []byte
	var err error
	if p := m["file"]; p != "" {
		raw, err = os.ReadFile(p)
	} else {
		// last bare arg? simplest: read stdin if no --file
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		cli.Die("reading receipt: %v", err)
	}
	var b verifier.ReceiptBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		cli.Die("parsing receipt JSON: %v", err)
	}
	var opt verifier.ReceiptOptions
	opt.RequireNotRetained = m["require-not-retained"] == "1"
	if m["expect-prev"] != "" {
		if opt.ExpectedPrevDigest, err = hex.DecodeString(m["expect-prev"]); err != nil {
			cli.Die("bad --expect-prev: %v", err)
		}
	}
	if (m["pin-x"] == "") != (m["pin-y"] == "") {
		cli.Die("--pin-x and --pin-y must be provided together")
	}
	if m["pin-x"] != "" {
		if opt.PinPubX, err = hex.DecodeString(m["pin-x"]); err != nil {
			cli.Die("bad --pin-x: %v", err)
		}
		if opt.PinPubY, err = hex.DecodeString(m["pin-y"]); err != nil {
			cli.Die("bad --pin-y: %v", err)
		}
	}
	res := verifier.VerifyReceipt(b, opt)
	if !res.OK {
		fmt.Printf("%s  %s\n", cli.Fail(), res.Reason)
		os.Exit(1)
	}
	r := res.Receipt
	fmt.Printf("%s  restraint receipt verified (signature + chain%s)\n", cli.Pass(),
		map[bool]string{true: " + not-retained", false: ""}[opt.RequireNotRetained])
	fmt.Printf("  session     : %s\n", r.Session)
	fmt.Printf("  batch       : %d\n", r.Batch)
	fmt.Printf("  input_hash  : %x  (processed, then discarded)\n", r.InputHash)
	fmt.Printf("  output_hash : %x  (the only thing emitted)\n", r.OutputHash)
	fmt.Printf("  retained    : %v\n", r.Retained)
	fmt.Printf("  prev_digest : %x\n", r.PrevDigest)
	fmt.Printf("  next_digest : %x\n", res.NextDigest)
}
