// he-verify — verify Honest Ear bound-output bundles.
//
// Single prover:
//
//	he-verify --nonce <hex> [--pin-x <hex> --pin-y <hex>] [--last-counter N] [bundle.json]
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
	nonceHex := flag.String("nonce", "", "expected fresh nonce (hex) — required")
	pinX := flag.String("pin-x", "", "pinned endorsement pub X (hex); use with --pin-y")
	pinY := flag.String("pin-y", "", "pinned endorsement pub Y (hex); use with --pin-x")
	lastCounter := flag.Uint64("last-counter", 0, "highest counter already accepted for this device")
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
	b, err := parseBundle(raw)
	if err != nil {
		cli.Die("%v", err)
	}

	opt := verifier.Options{ExpectedNonce: nonce, LastCounter: *lastCounter}
	if (*pinX == "") != (*pinY == "") {
		cli.Die("--pin-x and --pin-y must be provided together")
	}
	if *pinX != "" {
		if opt.PinPubX, err = hex.DecodeString(*pinX); err != nil {
			cli.Die("bad --pin-x: %v", err)
		}
		if opt.PinPubY, err = hex.DecodeString(*pinY); err != nil {
			cli.Die("bad --pin-y: %v", err)
		}
	}

	res := verifier.VerifyBundle(b, opt)
	if !res.OK {
		fmt.Printf("\033[1;31mFAIL\033[0m  %s\n", res.Reason)
		if res.Predicate != nil {
			printPredicate(res.Predicate)
		}
		os.Exit(1)
	}
	fmt.Printf("\033[1;32mPASS\033[0m  bound output verified (signature + freshness + anti-replay)\n")
	printPredicate(res.Predicate)
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
		fmt.Printf("\033[1;31mFAIL\033[0m  quorum not reached: %s\n", res.Reason)
		os.Exit(1)
	}
	fmt.Printf("\033[1;32mPASS\033[0m  %d-of-%d quorum reached by independent provers: %s\n",
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
}
