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
