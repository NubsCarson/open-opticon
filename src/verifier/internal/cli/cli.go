// Package cli holds the few helpers shared by the verifier command binaries, so
// there is exactly one definition of each (the cmd/* mains are separate
// package-main programs and cannot otherwise share unexported helpers).
package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// Die prints "error: <msg>" to stderr and exits with status 2.
func Die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(2)
}

// WriteJSON writes v as a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// colorEnabled reports whether to emit ANSI color: only when stdout is a
// terminal and NO_COLOR is unset, so piped/redirected output stays clean.
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// Pass and Fail return the PASS/FAIL banner, green/red on a TTY and plain text
// otherwise (one definition shared by he-verify and he-log).
func Pass() string {
	if colorEnabled() {
		return "\033[1;32mPASS\033[0m"
	}
	return "PASS"
}

func Fail() string {
	if colorEnabled() {
		return "\033[1;31mFAIL\033[0m"
	}
	return "FAIL"
}
