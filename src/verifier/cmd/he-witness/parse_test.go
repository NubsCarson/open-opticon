package main

import (
	"encoding/hex"
	"reflect"
	"testing"
)

// parsePeers is the anti-equivocation trust boundary: it maps each --peer spec to
// the PINNED peer name/url/pubX/pubY that checkPeers later verifies cosignatures
// under. Lock its happy-path behavior (field order, --peer= form, trailing-slash
// trim, ordering) so a silent regression can't weaken the pinned-peer guarantee.
// The error cases (bad field count, empty/dup name, bad hex) route through
// cli.Die -> os.Exit(2) and are intentionally not exercised here.
func TestParsePeersHappyPath(t *testing.T) {
	mk := func(name, url, xhex, yhex string) peer {
		x, _ := hex.DecodeString(xhex)
		y, _ := hex.DecodeString(yhex)
		return peer{name: name, url: url, pubX: x, pubY: y}
	}

	t.Run("single --peer, trailing slash trimmed", func(t *testing.T) {
		got := parsePeers([]string{"--peer", "p1,http://h:9000/,aabb,ccdd"})
		want := []peer{mk("p1", "http://h:9000", "aabb", "ccdd")}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("--peer= form parses equivalently", func(t *testing.T) {
		a := parsePeers([]string{"--peer", "p1,http://h:9000,aabb,ccdd"})
		b := parsePeers([]string{"--peer=p1,http://h:9000,aabb,ccdd"})
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("--peer X (%+v) != --peer=X (%+v)", a, b)
		}
	})

	t.Run("multiple distinct peers preserve order", func(t *testing.T) {
		got := parsePeers([]string{
			"--peer", "a,http://x:1,1111,2222",
			"--peer", "b,http://y:2/,3333,4444",
		})
		want := []peer{mk("a", "http://x:1", "1111", "2222"), mk("b", "http://y:2", "3333", "4444")}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("no --peer args yields nil", func(t *testing.T) {
		if got := parsePeers([]string{"--name", "w1", "--log-url", "http://l"}); got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
	})
}

func TestHelpRequested(t *testing.T) {
	// The `<sub> --help` gesture: the help token leads (args = os.Args[2:]).
	for _, a := range []string{"-h", "--help", "help"} {
		if !helpRequested([]string{a}, usageCheck) {
			t.Errorf("helpRequested should be true for leading %q", a)
		}
	}
	// A help token that is NOT leading — i.e. a flag's VALUE — must NOT trigger help
	// (else `--name help` would silently no-op the command with a success exit).
	if helpRequested([]string{"--name", "help"}, usageCheck) {
		t.Error("helpRequested matched a flag VALUE of 'help'; it must only match the leading token")
	}
	if helpRequested([]string{"--name", "w1", "--key", "ab"}, usageCheck) {
		t.Error("helpRequested should be false when no help token is present")
	}
}
