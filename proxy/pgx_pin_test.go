package proxy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// verifiedPgxVersion is the github.com/jackc/pgx/v5 version whose pgproto3
// read/write field disjointness was checked by hand. relayPostgres runs a
// concurrent Send and Receive on the same Frontend/Backend, which is only safe
// because the read path and write path touch disjoint struct fields in this
// version. pgproto3 does not document Send/Receive as concurrency-safe.
const verifiedPgxVersion = "v5.10.0"

// TestPgxVersionPinnedForRelayConcurrencyInvariant is a tripwire: it fails when
// go.mod's pgx/v5 requirement moves off the verified version, so a contributor
// must re-verify the relay's concurrency assumption before the bump lands
// rather than discovering a data race under load.
func TestPgxVersionPinnedForRelayConcurrencyInvariant(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("cannot locate test file path")
	}
	gomod := filepath.Join(filepath.Dir(thisFile), "..", "go.mod")
	data, err := os.ReadFile(gomod)
	if err != nil {
		t.Skipf("cannot read go.mod: %v", err)
	}

	var got string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "github.com/jackc/pgx/v5" {
			got = fields[1]
			break
		}
	}
	if got == "" {
		t.Fatal("github.com/jackc/pgx/v5 requirement not found in go.mod")
	}
	if got != verifiedPgxVersion {
		t.Fatalf("pgx/v5 is %s in go.mod but the relay concurrency invariant was verified against %s.\n"+
			"Re-verify that pgproto3's read and write paths remain disjoint struct fields "+
			"(see relayPostgres in postgres.go), then update verifiedPgxVersion.", got, verifiedPgxVersion)
	}
}
