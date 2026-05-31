package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newServer() *server {
	return &server{sessions: map[string]*session{}, baseURL: "http://x", ttl: time.Minute}
}

func TestStatusLifecycle(t *testing.T) {
	s := newServer()
	s.sessions["sid1"] = &session{nonce: []byte{1}, createdAt: time.Now()}

	get := func(sid string) map[string]string {
		rr := httptest.NewRecorder()
		s.handleStatus(rr, httptest.NewRequest(http.MethodGet, "/status?session="+sid, nil))
		var m map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatalf("status json: %v", err)
		}
		return m
	}

	if m := get("nope"); m["state"] != "unknown" {
		t.Errorf("unknown session state = %q", m["state"])
	}
	if m := get("sid1"); m["state"] != "pending" {
		t.Errorf("fresh session state = %q, want pending", m["state"])
	}
	// simulate an attest having recorded a verdict
	s.sessions["sid1"].verdict = "PASS"
	s.sessions["sid1"].event = "alarm_tone"
	m := get("sid1")
	if m["state"] != "done" || m["verdict"] != "PASS" || m["event"] != "alarm_tone" {
		t.Errorf("done status = %+v", m)
	}
}

func TestVerifyPageServesHTML(t *testing.T) {
	s := newServer()
	rr := httptest.NewRecorder()
	s.handleVerifyPage(rr, httptest.NewRequest(http.MethodGet, "/v?session=abc123", nil))
	body := rr.Body.String()
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(body, "live verification") || !strings.Contains(body, "abc123") {
		t.Errorf("verify page missing expected content")
	}
}
