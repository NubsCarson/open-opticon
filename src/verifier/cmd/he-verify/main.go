// he-verify — verify Honest Ear bound-output bundles.
//
// Single prover:
//
//	he-verify --nonce <hex> [--pin-x <hex> --pin-y <hex>] [--last-counter N] [--expect-prev <hex>] [bundle.json]
//
// Quorum (k-of-n independent provers):
//
//	he-verify --nonce <hex> --quorum 2 \
//	    --root tee-a:<pubXhex>:<pubYhex> --root tpm-b:<pubXhex>:<pubYhex> ... \
//	    a.json b.json c.json
//
// Single-prover mode reads one bundle from the file argument or stdin; quorum
// mode reads one bundle per file argument. Exits 0 on PASS, 1 on FAIL, 2 on
// usage/IO error.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
)

// repeatable --root flag.
type rootList []string

func (r *rootList) String() string { return strings.Join(*r, ",") }
func (r *rootList) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), `he-verify — verify Honest Ear bound-output bundles.

  single: he-verify --nonce <hex> [--pin-x <hex> --pin-y <hex>] [--last-counter N] [--expect-prev <hex>] [bundle.json]
  quorum: he-verify --nonce <hex> --quorum K --root name:<pubXhex>:<pubYhex> [--root ...] a.json b.json ...

Single mode reads one bundle from the file arg or stdin; quorum reads one per file arg.
Exits 0 on PASS, 1 on FAIL, 2 on usage error.

flags:
`)
		flag.PrintDefaults()
	}
	nonceHex := flag.String("nonce", "", "expected fresh nonce (hex) — required")
	pinX := flag.String("pin-x", "", "pinned endorsement pub X (hex); use with --pin-y")
	pinY := flag.String("pin-y", "", "pinned endorsement pub Y (hex); use with --pin-x")
	lastCounter := flag.Uint64("last-counter", 0, "highest counter already accepted for this device")
	expectPrev := flag.String("expect-prev", "", "expected prev_digest (hex) — the digest this window must chain from (stream gap detection); use 64 zeros for the genesis window")
	cose := flag.Bool("cose", false, "verify a COSE_Sign1 (RFC 9052) bundle ({schema,cose,pub_x,pub_y}) instead of the raw envelope")
	quorum := flag.Int("quorum", 0, "require k-of-n independent provers (quorum mode)")
	var roots rootList
	flag.Var(&roots, "root", "enrolled prover as name:pubXhex:pubYhex (repeatable, quorum mode)")
	flag.Parse()

	if *nonceHex == "" {
		cli.Die("--nonce is required")
	}
	nonce, err := hex.DecodeString(*nonceHex)
	if err != nil {
		cli.Die("bad --nonce hex: %v", err)
	}

	if *quorum > 0 {
		runQuorum(nonce, *quorum, roots, *lastCounter)
		return
	}

	var raw []byte
	if flag.NArg() >= 1 {
		raw, err = os.ReadFile(flag.Arg(0))
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		cli.Die("reading bundle: %v", err)
	}
	opt := verifier.Options{ExpectedNonce: nonce, LastCounter: *lastCounter}
	if *expectPrev != "" {
		if opt.ExpectedPrevDigest, err = hex.DecodeString(*expectPrev); err != nil || len(opt.ExpectedPrevDigest) != 32 {
			cli.Die("--expect-prev must be 32 bytes hex")
		}
	}
	if (*pinX == "") != (*pinY == "") {
		cli.Die("--pin-x and --pin-y must be provided together")
	}
	if *pinX != "" {
		if opt.PinPubX, err = hex.DecodeString(*pinX); err != nil || len(opt.PinPubX) != 32 {
			cli.Die("--pin-x must be 32 bytes hex")
		}
		if opt.PinPubY, err = hex.DecodeString(*pinY); err != nil || len(opt.PinPubY) != 32 {
			cli.Die("--pin-y must be 32 bytes hex")
		}
	}

	// COSE_Sign1 mode verifies the standards-aligned envelope; same gates apply.
	var res verifier.VerifyResult
	if *cose {
		var cb verifier.COSEBundle
		if jerr := json.Unmarshal(raw, &cb); jerr != nil {
			cli.Die("parsing COSE bundle JSON: %v", jerr)
		}
		res = verifier.VerifyCOSEBundle(cb, opt)
	} else {
		b, perr := parseBundle(raw)
		if perr != nil {
			cli.Die("%v", perr)
		}
		res = verifier.VerifyBundle(b, opt)
	}
	if !res.OK {
		fmt.Printf("%s  %s\n", cli.Fail(), res.Reason)
		if res.Predicate != nil {
			printPredicate(res.Predicate)
		}
		os.Exit(1)
	}
	fmt.Printf("%s  bound output verified (signature + freshness + anti-replay)\n", cli.Pass())
	printPredicate(res.Predicate)
	// Emit the digest the NEXT window in this device's stream must carry as its
	// prev_digest. A monitor feeds this back via --expect-prev to detect a
	// suppressed window (the chain would break).
	fmt.Printf("  next_digest  : %x\n", res.NextDigest)
}

func runQuorum(nonce []byte, k int, rootSpecs rootList, lastCounter uint64) {
	roots := make([]verifier.Prover, 0, len(rootSpecs))
	for _, spec := range rootSpecs {
		parts := strings.Split(spec, ":")
		if len(parts) != 3 {
			cli.Die("--root must be name:pubXhex:pubYhex, got %q", spec)
		}
		px, err := hex.DecodeString(parts[1])
		if err != nil {
			cli.Die("bad pub X for root %q: %v", parts[0], err)
		}
		py, err := hex.DecodeString(parts[2])
		if err != nil {
			cli.Die("bad pub Y for root %q: %v", parts[0], err)
		}
		roots = append(roots, verifier.Prover{Name: parts[0], PubX: px, PubY: py})
	}

	var bundles []verifier.Bundle
	for _, path := range flag.Args() {
		raw, err := os.ReadFile(path)
		if err != nil {
			cli.Die("reading %s: %v", path, err)
		}
		b, err := parseBundle(raw)
		if err != nil {
			cli.Die("%s: %v", path, err)
		}
		bundles = append(bundles, b)
	}

	res := verifier.VerifyQuorum(bundles, verifier.QuorumOptions{
		ExpectedNonce: nonce, Roots: roots, Threshold: k, LastCounter: lastCounter,
	})
	if !res.OK {
		fmt.Printf("%s  quorum not reached: %s\n", cli.Fail(), res.Reason)
		os.Exit(1)
	}
	fmt.Printf("%s  %d-of-%d quorum reached by independent provers: %s\n", cli.Pass(),
		k, len(roots), strings.Join(res.PassedRoots, ", "))
	fmt.Printf("  agreed event : %s\n", res.Event)
	fmt.Printf("  (only the event class is quorum-agreed; counters/presence are per-prover)\n")
}

func parseBundle(raw []byte) (verifier.Bundle, error) {
	var b verifier.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, fmt.Errorf("parsing bundle JSON: %w", err)
	}
	return b, nil
}

func printPredicate(p *verifier.Predicate) {
	fmt.Printf("  event        : %s\n", p.EventName())
	fmt.Printf("  presence     : %d\n", p.Presence)
	fmt.Printf("  voice_active : %v\n", p.VoiceActive)
	fmt.Printf("  frames       : %d  (~%d ms observed)\n", p.Frames, p.WindowMs)
	fmt.Printf("  counter      : %d\n", p.Counter)
	fmt.Printf("  nonce        : %x\n", p.Nonce)
	fmt.Printf("  config_hash  : %x\n", p.ConfigHash)
	fmt.Printf("  input_hash   : %x\n", p.InputHash)
	fmt.Printf("  prev_digest  : %x\n", p.PrevDigest)
}
