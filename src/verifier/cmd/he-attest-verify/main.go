// he-attest-verify — host-side verification of a PSA attestation token (EAT).
//
// Checks the parts of firmware attestation that are verifiable offline, without
// Veraison or the rig: the COSE_Sign1 ES256 signature under a pinned attestation
// key, the EAT profile, the freshness nonce, and that every software component's
// measurement-value is a published reference value. On the rig, Veraison does the
// full appraisal; this is the laptop-checkable core (see VerifyPSAToken).
//
//	he-attest-verify --token <file|hex> --pin-x <hex> --pin-y <hex> \
//	    --nonce <hex> [--profile P] [--ref <measHex> ...]
//
// Exits 0 if the token verifies, 1 if it does not, 2 on usage/IO error.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	verifier "honest-ear/verifier"
	"honest-ear/verifier/internal/cli"
)

type refList [][]byte

func (r *refList) String() string { return fmt.Sprintf("%d refs", len(*r)) }
func (r *refList) Set(v string) error {
	b, err := hex.DecodeString(v)
	if err != nil {
		return err
	}
	*r = append(*r, b)
	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), `he-attest-verify — verify a PSA attestation token (EAT) offline.

  he-attest-verify --token <file|hex> --pin-x <hex> --pin-y <hex> --nonce <hex> [--profile P] [--ref <measHex> ...]

Checks: COSE_Sign1 ES256 signature under the pinned key, eat_profile, freshness
nonce, and that every software-component measurement is a published reference
(--ref, repeatable). On the rig Veraison does the full appraisal; this is the
offline-checkable core. Exits 0 on PASS, 1 on FAIL, 2 on usage error.

flags:
`)
		flag.PrintDefaults()
	}
	tokenArg := flag.String("token", "", "token as a file path or raw hex — required")
	pinX := flag.String("pin-x", "", "pinned attestation pub X (hex) — required")
	pinY := flag.String("pin-y", "", "pinned attestation pub Y (hex) — required")
	nonceHex := flag.String("nonce", "", "expected freshness nonce (hex) — required")
	profile := flag.String("profile", verifier.PSAProfile, "expected eat_profile")
	var refs refList
	flag.Var(&refs, "ref", "a published reference measurement-value (hex); repeatable")
	flag.Parse()

	if *tokenArg == "" || *pinX == "" || *pinY == "" || *nonceHex == "" {
		cli.Die("--token, --pin-x, --pin-y and --nonce are required")
	}
	token := readToken(*tokenArg)
	px, err := hex.DecodeString(*pinX)
	if err != nil {
		cli.Die("bad --pin-x: %v", err)
	}
	py, err := hex.DecodeString(*pinY)
	if err != nil {
		cli.Die("bad --pin-y: %v", err)
	}
	nonce, err := hex.DecodeString(*nonceHex)
	if err != nil {
		cli.Die("bad --nonce: %v", err)
	}

	claims, err := verifier.VerifyPSAToken(token, px, py, verifier.PSAOptions{
		ExpectedNonce:         nonce,
		ExpectedProfile:       *profile,
		ReferenceMeasurements: refs,
	})
	if err != nil {
		fmt.Printf("%s  %v\n", cli.Fail(), err)
		if claims != nil {
			printClaims(claims)
		}
		os.Exit(1)
	}
	fmt.Printf("%s  PSA token verified (signature + profile + freshness + reference measurements)\n", cli.Pass())
	printClaims(claims)
}

// readToken accepts either a path to a file (hex or raw bytes) or a raw hex string.
func readToken(arg string) []byte {
	if b, err := os.ReadFile(arg); err == nil {
		s := strings.TrimSpace(string(b))
		if raw, err := hex.DecodeString(s); err == nil {
			return raw
		}
		return b // file held raw token bytes
	}
	raw, err := hex.DecodeString(strings.TrimSpace(arg))
	if err != nil {
		cli.Die("--token is neither a readable file nor valid hex")
	}
	return raw
}

func printClaims(c *verifier.PSAClaims) {
	fmt.Printf("  eat_profile      : %s\n", c.Profile)
	fmt.Printf("  nonce            : %x\n", c.Nonce)
	fmt.Printf("  instance_id      : %x\n", c.InstanceID)
	fmt.Printf("  implementation_id: %x\n", c.ImplementationID)
	for i, sc := range c.SoftwareComponents {
		fmt.Printf("  sw[%d] %-8s measurement=%x signer=%x\n",
			i, sc.MeasurementType, sc.MeasurementValue, sc.SignerID)
	}
}
