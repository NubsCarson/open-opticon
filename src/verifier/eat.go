package verifier

// Host-side verification of a PSA Attestation Token (an EAT: COSE_Sign1 wrapping
// CBOR PSA claims, profile "http://arm.com/psa/2.0.0"). On the rig, this token is
// appraised by Veraison; this lets a host check the parts that are verifiable
// offline — the ES256 signature under a pinned attestation key, the EAT profile,
// the freshness nonce, and (the core of appraisal) that every software
// component's measurement-value is a published reference value. It reuses the
// COSE_Sign1 parser/verification (cose.go) and the stdlib-only cborReader.
//
// HONEST SCOPE: this proves "the token is signed by the pinned key AND its
// measurements match the published references AND it echoes our nonce" — the
// laptop-checkable core of what Veraison does. It does NOT replace Veraison's
// full endorsement/trust-anchor provisioning and policy; a real Veraison-issued
// token (vs. the test-minted one this is tested against) is the rig step.

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

// PSA EAT claim keys (draft-tschofenig-rats-psa-token / Arm PSA profile).
const (
	psaKeyNonce          = 10   // bstr — the verifier's freshness challenge
	psaKeyInstanceID     = 256  // bstr — psa-instance-id
	psaKeyProfile        = 265  // tstr — eat_profile
	psaKeyClientID       = 2394 // int  — psa-client-id
	psaKeyLifecycle      = 2395 // int  — psa-security-lifecycle
	psaKeyImplementation = 2396 // bstr — psa-implementation-id
	psaKeySoftware       = 2399 // array of component maps — psa-software-components
	// software-component sub-claim keys:
	swKeyMeasurementType  = 1 // tstr
	swKeyMeasurementValue = 2 // bstr
	swKeySignerID         = 5 // bstr
)

// PSAProfile is the EAT profile string this verifier expects by default.
const PSAProfile = "http://arm.com/psa/2.0.0"

// SWComponent is one entry of psa-software-components.
type SWComponent struct {
	MeasurementType  string
	MeasurementValue []byte
	SignerID         []byte
}

// PSAClaims is the subset of PSA token claims this verifier extracts.
type PSAClaims struct {
	Profile            string
	Nonce              []byte
	InstanceID         []byte
	ImplementationID   []byte
	SoftwareComponents []SWComponent
}

// PSAOptions pins what a valid token must say.
type PSAOptions struct {
	// ExpectedNonce is the fresh challenge the token must echo. Required.
	ExpectedNonce []byte
	// ExpectedProfile, if set, must equal the token's eat_profile (defaults to PSAProfile).
	ExpectedProfile string
	// ReferenceMeasurements, if non-empty, is the set of published, acceptable
	// measurement-values; EVERY software component's measurement-value must be in
	// it (this is the offline analogue of Veraison's reference-value appraisal).
	ReferenceMeasurements [][]byte
}

// VerifyPSAToken verifies the COSE_Sign1 signature under (pubX,pubY), then checks
// the profile, the freshness nonce, and that every software component's
// measurement matches a published reference. Returns the decoded claims on success.
func VerifyPSAToken(token, pubX, pubY []byte, opt PSAOptions) (*PSAClaims, error) {
	protBstr, payload, payloadBstr, sig, err := parseCOSESign1(token)
	if err != nil {
		return nil, fmt.Errorf("cose: %w", err)
	}
	if err := verifySig(coseSigStruct(protBstr, payloadBstr), sig, pubX, pubY); err != nil {
		return nil, fmt.Errorf("token signature: %w", err)
	}
	claims, err := parsePSAClaims(payload)
	if err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}

	wantProfile := opt.ExpectedProfile
	if wantProfile == "" {
		wantProfile = PSAProfile
	}
	if claims.Profile != wantProfile {
		return claims, fmt.Errorf("eat_profile %q != expected %q", claims.Profile, wantProfile)
	}

	if len(opt.ExpectedNonce) == 0 {
		return claims, errors.New("no expected nonce supplied")
	}
	if subtle.ConstantTimeCompare(claims.Nonce, opt.ExpectedNonce) != 1 {
		return claims, errors.New("nonce mismatch (stale/replayed token)")
	}

	if len(opt.ReferenceMeasurements) > 0 {
		if len(claims.SoftwareComponents) == 0 {
			return claims, errors.New("no software components to appraise")
		}
		for _, c := range claims.SoftwareComponents {
			if !measurementInSet(c.MeasurementValue, opt.ReferenceMeasurements) {
				return claims, fmt.Errorf("measurement %x is not a published reference value", c.MeasurementValue)
			}
		}
	}
	return claims, nil
}

func measurementInSet(m []byte, set [][]byte) bool {
	for _, r := range set {
		if subtle.ConstantTimeCompare(m, r) == 1 {
			return true
		}
	}
	return false
}

// parsePSAClaims decodes the CBOR claims map (the COSE payload) into PSAClaims.
// Unknown claims are skipped; required ones are read by their PSA key.
func parsePSAClaims(b []byte) (*PSAClaims, error) {
	r := &cborReader{b: b}
	major, n, err := r.readHead()
	if err != nil {
		return nil, err
	}
	if major != 5 {
		return nil, fmt.Errorf("claims is not a CBOR map (major %d)", major)
	}
	c := &PSAClaims{}
	for i := uint64(0); i < n; i++ {
		key, err := r.readUint()
		if err != nil {
			return nil, fmt.Errorf("claim key: %w", err)
		}
		switch key {
		case psaKeyProfile:
			c.Profile, err = r.readTstr()
		case psaKeyNonce:
			c.Nonce, err = r.readBstr()
		case psaKeyInstanceID:
			c.InstanceID, err = r.readBstr()
		case psaKeyImplementation:
			c.ImplementationID, err = r.readBstr()
		case psaKeySoftware:
			c.SoftwareComponents, err = r.readSoftwareComponents()
		default:
			err = r.skipValue() // claims we don't interpret (client-id, lifecycle, ...)
		}
		if err != nil {
			return nil, fmt.Errorf("claim %d: %w", key, err)
		}
	}
	if r.pos != len(b) {
		return nil, errors.New("trailing bytes after PSA claims map")
	}
	return c, nil
}

// readSoftwareComponents reads psa-software-components: an array of maps, each
// with measurement-type (1), measurement-value (2), signer-id (5).
func (r *cborReader) readSoftwareComponents() ([]SWComponent, error) {
	major, n, err := r.readHead()
	if err != nil {
		return nil, err
	}
	if major != 4 {
		return nil, fmt.Errorf("software-components is not an array (major %d)", major)
	}
	out := make([]SWComponent, 0, n)
	for i := uint64(0); i < n; i++ {
		cm, cn, err := r.readHead()
		if err != nil {
			return nil, err
		}
		if cm != 5 {
			return nil, fmt.Errorf("software component is not a map (major %d)", cm)
		}
		var comp SWComponent
		for j := uint64(0); j < cn; j++ {
			sk, err := r.readUint()
			if err != nil {
				return nil, err
			}
			switch sk {
			case swKeyMeasurementType:
				comp.MeasurementType, err = r.readTstr()
			case swKeyMeasurementValue:
				comp.MeasurementValue, err = r.readBstr()
			case swKeySignerID:
				comp.SignerID, err = r.readBstr()
			default:
				err = r.skipValue()
			}
			if err != nil {
				return nil, err
			}
		}
		out = append(out, comp)
	}
	return out, nil
}

// readTstr reads a CBOR text string (major type 3).
func (r *cborReader) readTstr() (string, error) {
	major, n, err := r.readHead()
	if err != nil {
		return "", err
	}
	if major != 3 {
		return "", fmt.Errorf("expected text string, got major type %d", major)
	}
	if n > uint64(len(r.b)-r.pos) {
		return "", errors.New("text string length exceeds buffer")
	}
	s := string(r.b[r.pos : r.pos+int(n)])
	r.pos += int(n)
	return s, nil
}
