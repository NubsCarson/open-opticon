// he-verify — verify a single Honest Ear bound-output bundle.
//
//	he-verify --nonce <hex> [--pin-x <hex> --pin-y <hex>] [--last-counter N] [bundle.json]
//
// Reads the bundle from the file argument or stdin. Exits 0 on PASS, 1 on FAIL.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	verifier "honest-ear/verifier"
)

func main() {
	nonceHex := flag.String("nonce", "", "expected fresh nonce (hex) — required")
	pinX := flag.String("pin-x", "", "pinned endorsement pub X (hex), optional")
	pinY := flag.String("pin-y", "", "pinned endorsement pub Y (hex), optional")
	lastCounter := flag.Uint64("last-counter", 0, "highest counter already accepted for this device")
	flag.Parse()

	if *nonceHex == "" {
		fmt.Fprintln(os.Stderr, "error: --nonce is required")
		os.Exit(2)
	}
	nonce, err := hex.DecodeString(*nonceHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: bad --nonce hex: %v\n", err)
		os.Exit(2)
	}

	var raw []byte
	if flag.NArg() >= 1 {
		raw, err = os.ReadFile(flag.Arg(0))
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading bundle: %v\n", err)
		os.Exit(2)
	}

	var b verifier.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing bundle JSON: %v\n", err)
		os.Exit(2)
	}

	opt := verifier.Options{ExpectedNonce: nonce, LastCounter: *lastCounter}
	if *pinX != "" || *pinY != "" {
		if opt.PinPubX, err = hex.DecodeString(*pinX); err != nil {
			fmt.Fprintf(os.Stderr, "error: bad --pin-x: %v\n", err)
			os.Exit(2)
		}
		if opt.PinPubY, err = hex.DecodeString(*pinY); err != nil {
			fmt.Fprintf(os.Stderr, "error: bad --pin-y: %v\n", err)
			os.Exit(2)
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

func printPredicate(p *verifier.Predicate) {
	fmt.Printf("  event        : %s\n", p.EventName())
	fmt.Printf("  presence     : %d\n", p.Presence)
	fmt.Printf("  voice_active : %v\n", p.VoiceActive)
	fmt.Printf("  frames       : %d  (~%d ms observed)\n", p.Frames, p.WindowMs)
	fmt.Printf("  counter      : %d\n", p.Counter)
	fmt.Printf("  nonce        : %x\n", p.Nonce)
	fmt.Printf("  config_hash  : %x\n", p.ConfigHash)
}
