package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildHeLog compiles the he-log binary once for the exec-based CLI tests (the
// "add" guards exit via cli.Die -> os.Exit(2), which can't be exercised in-process).
func buildHeLog(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "he-log")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build he-log: %v\n%s", err, out)
	}
	return bin
}

// he-log writes a tamper-evident, append-only RFC 6962 log, so `add` must FAIL
// CLOSED (exit 2) rather than silently append an empty or truncated leaf with a
// green "added at index N" when the entry is missing, word-split by the shell, or
// empty. Regression guard for the fail-open gap on the one tool that must not.
func TestAddRejectsBadArgs(t *testing.T) {
	bin := buildHeLog(t)
	logPath := filepath.Join(t.TempDir(), "L.json")

	cases := []struct {
		name string
		args []string
		want string // substring expected on stderr
	}{
		{"no entry", []string{"add", "--log", logPath}, "exactly one"},
		{"extra args (shell-split hex)", []string{"add", "--log", logPath, "dead", "beef"}, "exactly one"},
		{"present but empty hex", []string{"add", "--log", logPath, ""}, "non-empty"},
		{"invalid hex", []string{"add", "--log", logPath, "xyz"}, "must be hex"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := exec.Command(bin, c.args...).CombinedOutput()
			ee, ok := err.(*exec.ExitError)
			if !ok || ee.ExitCode() != 2 {
				t.Fatalf("exit = %v (want exit 2); output: %s", err, out)
			}
			if !strings.Contains(string(out), c.want) {
				t.Errorf("stderr = %q, want substring %q", out, c.want)
			}
			// A rejected add must not have created/written the log (guards fire
			// before load/save), so the file must still not exist.
			if _, statErr := os.Stat(logPath); statErr == nil {
				t.Errorf("rejected add wrote the log file; it must fail before save")
			}
		})
	}

	// Sanity: a single valid hex entry still appends and creates the log (exit 0).
	if out, err := exec.Command(bin, "add", "--log", logPath, "deadbeef").CombinedOutput(); err != nil {
		t.Fatalf("valid add failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("valid add did not create the log: %v", err)
	}
}
