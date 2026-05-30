package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These exercise the /listen input-validation early-returns, which run before
// any exec of the sim binary — so they need no he-attest-sim present.
func TestListenValidation(t *testing.T) {
	h := listenHandler("/nonexistent-sim")

	cases := []struct {
		name       string
		method     string
		body       []byte
		wantStatus int
		wantReason string // substring expected in the JSON reason (POST cases)
	}{
		{"GET rejected", http.MethodGet, nil, http.StatusMethodNotAllowed, ""},
		{"empty body", http.MethodPost, nil, http.StatusOK, "no audio"},
		{"too short", http.MethodPost, bytes.Repeat([]byte{0}, 32), http.StatusOK, "no audio"},
		{"odd length", http.MethodPost, bytes.Repeat([]byte{1}, 101), http.StatusOK, "16-bit"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "/listen", bytes.NewReader(c.body))
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			if c.wantReason != "" {
				var res result
				if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
					t.Fatalf("bad JSON: %v", err)
				}
				if res.Verified {
					t.Error("verified=true on an invalid request")
				}
				if !strings.Contains(res.Reason, c.wantReason) {
					t.Errorf("reason = %q, want substring %q", res.Reason, c.wantReason)
				}
			}
		})
	}
}
