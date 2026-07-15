package gatekeeper

// config_topology_test.go tests resolveListenTopology, the pure function
// that decides whether the proxy and Postgres listeners collapse onto one
// shared, single-port listener (see demux.go in the proxy package) purely
// from port/host equality — there is no separate config flag.

import (
	"strings"
	"testing"
)

func TestResolveListenTopology_NoPostgresNeverMultiplexes(t *testing.T) {
	cfg := &Config{Proxy: ProxyConfig{Port: 8080, Host: "127.0.0.1"}}
	topo, err := resolveListenTopology(cfg)
	if err != nil {
		t.Fatalf("resolveListenTopology: %v", err)
	}
	if topo.multiplex {
		t.Error("multiplex = true with no postgres configured, want false")
	}
}

func TestResolveListenTopology_EqualNonZeroPortsAndHostsMultiplex(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 5432, Host: "127.0.0.1"},
		Postgres: &PostgresConfig{Port: 5432},
	}
	topo, err := resolveListenTopology(cfg)
	if err != nil {
		t.Fatalf("resolveListenTopology: %v", err)
	}
	if !topo.multiplex {
		t.Error("multiplex = false with equal proxy.port/postgres.port and matching hosts, want true")
	}
}

func TestResolveListenTopology_EqualPortsExplicitSameHostMultiplexes(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 5432, Host: "0.0.0.0"},
		Postgres: &PostgresConfig{Port: 5432, Host: "0.0.0.0"},
	}
	topo, err := resolveListenTopology(cfg)
	if err != nil {
		t.Fatalf("resolveListenTopology: %v", err)
	}
	if !topo.multiplex {
		t.Error("multiplex = false with explicit matching hosts, want true")
	}
}

// TestResolveListenTopology_EqualPortsDifferentHostsErrors pins the fatal,
// ambiguous-bind error: two listeners can't share one port but bind
// different addresses.
func TestResolveListenTopology_EqualPortsDifferentHostsErrors(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 5432, Host: "127.0.0.1"},
		Postgres: &PostgresConfig{Port: 5432, Host: "10.0.0.5"},
	}
	_, err := resolveListenTopology(cfg)
	if err == nil {
		t.Fatal("resolveListenTopology succeeded with equal ports but different hosts, want an error")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") || !strings.Contains(err.Error(), "10.0.0.5") {
		t.Errorf("error = %q, want it to name both conflicting hosts", err)
	}
}

// TestResolveListenTopology_MismatchedProxyProtocolErrors pins the fatal
// error for a shared listener with disagreeing PROXY protocol settings: one
// physical listener can only have one PROXY protocol setting.
func TestResolveListenTopology_MismatchedProxyProtocolErrors(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 5432, Host: "127.0.0.1", ProxyProtocol: true},
		Postgres: &PostgresConfig{Port: 5432, ProxyProtocol: false},
	}
	_, err := resolveListenTopology(cfg)
	if err == nil {
		t.Fatal("resolveListenTopology succeeded with mismatched proxy_protocol settings, want an error")
	}
	if !strings.Contains(err.Error(), "proxy_protocol") {
		t.Errorf("error = %q, want it to mention proxy_protocol", err)
	}
}

// TestResolveListenTopology_MatchingProxyProtocolMultiplexes is the
// converse of the mismatch case: when both sides explicitly agree, the
// shared listener is allowed and inherits that setting.
func TestResolveListenTopology_MatchingProxyProtocolMultiplexes(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 5432, Host: "127.0.0.1", ProxyProtocol: true},
		Postgres: &PostgresConfig{Port: 5432, ProxyProtocol: true},
	}
	topo, err := resolveListenTopology(cfg)
	if err != nil {
		t.Fatalf("resolveListenTopology: %v", err)
	}
	if !topo.multiplex {
		t.Error("multiplex = false with matching proxy_protocol settings, want true")
	}
}

// TestResolveListenTopology_DistinctPortsNeverMultiplex pins today's default
// two-listener path, unchanged.
func TestResolveListenTopology_DistinctPortsNeverMultiplex(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 8080, Host: "127.0.0.1"},
		Postgres: &PostgresConfig{Port: 5432},
	}
	topo, err := resolveListenTopology(cfg)
	if err != nil {
		t.Fatalf("resolveListenTopology: %v", err)
	}
	if topo.multiplex {
		t.Error("multiplex = true with distinct ports, want false")
	}
}

// TestResolveListenTopology_BothPortsZeroNeverMultiplex is a regression pin
// for a subtle trap: Port: 0 on both sides means "ask the OS for an
// ephemeral port" on each listener independently, not "these are the same
// port." Treating 0 == 0 as a multiplex trigger would silently change
// behavior for every config (and every test in this suite) that leaves the
// port unset on both listeners, in violation of "distinct ports leave the
// two-listener path unchanged" — port 0 on both sides isn't a declared
// shared port at all, so it must never trigger multiplexing.
func TestResolveListenTopology_BothPortsZeroNeverMultiplex(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Postgres: &PostgresConfig{Port: 0},
	}
	topo, err := resolveListenTopology(cfg)
	if err != nil {
		t.Fatalf("resolveListenTopology: %v", err)
	}
	if topo.multiplex {
		t.Error("multiplex = true with both ports left at 0, want false (0 means \"OS-assigned\", not \"shared\")")
	}
}

// TestResolveListenTopology_PostgresHostDefaultsToResolvedProxyHost mirrors
// the existing gatekeeper.go rule (postgres.host defaults to the same host
// the proxy listener resolved to, including the 127.0.0.1 default when
// proxy.host is empty) so multiplex detection agrees with it exactly.
func TestResolveListenTopology_PostgresHostDefaultsToResolvedProxyHost(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 5432}, // Host left empty -> defaultProxyHost
		Postgres: &PostgresConfig{Port: 5432},
	}
	topo, err := resolveListenTopology(cfg)
	if err != nil {
		t.Fatalf("resolveListenTopology: %v", err)
	}
	if !topo.multiplex {
		t.Error("multiplex = false when both hosts default to the same resolved address, want true")
	}
	if topo.proxyHost != defaultProxyHost {
		t.Errorf("proxyHost = %q, want %q", topo.proxyHost, defaultProxyHost)
	}
	if topo.pgHost != defaultProxyHost {
		t.Errorf("pgHost = %q, want %q", topo.pgHost, defaultProxyHost)
	}
}
