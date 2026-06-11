package proxy

// pgtest_test.go provides a fake Postgres server for tests. It is a real TLS
// Postgres wire-protocol server that requires SCRAM-SHA-256 authentication and
// genuinely verifies it (via xdg-go/scram's server side), then answers simple
// Query messages. Later Postgres data-plane tests build on this fake.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// testServerCert returns a self-signed ECDSA P-256 certificate valid for
// dnsName and a cert pool that trusts it.
func testServerCert(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{dnsName},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, pool
}

// fakePostgresServer is a TLS Postgres server that requires and verifies
// SCRAM-SHA-256 authentication, then answers simple Query messages.
type fakePostgresServer struct {
	t        *testing.T
	addr     string
	certPool *x509.CertPool // trusts the server's own certificate
	user     string
	password string

	cert        tls.Certificate
	scramServer *scram.Server

	mu        sync.Mutex
	authOK    int
	authFail  int
	lastQuery string
}

func (f *fakePostgresServer) counts() (authOK, authFail int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authOK, f.authFail
}

func (f *fakePostgresServer) queriedLast() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastQuery
}

// startFakePostgres starts a fake Postgres server on 127.0.0.1:0. The listener
// is closed via t.Cleanup.
func startFakePostgres(t *testing.T, dnsName, user, password string) *fakePostgresServer {
	t.Helper()

	cert, pool := testServerCert(t, dnsName)

	// Build the stored SCRAM credentials a real server would keep instead of
	// the plaintext password. The scram client is only used here as a
	// convenient way to derive them.
	client, err := scram.SHA256.NewClient(user, password, "")
	if err != nil {
		t.Fatalf("scram client: %v", err)
	}
	stored := client.GetStoredCredentials(scram.KeyFactors{Salt: "pinned-salt-0123", Iters: 4096})
	scramServer, err := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) {
		return stored, nil
	})
	if err != nil {
		t.Fatalf("scram server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	f := &fakePostgresServer{
		t:           t,
		addr:        ln.Addr().String(),
		certPool:    pool,
		user:        user,
		password:    password,
		cert:        cert,
		scramServer: scramServer,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()

	return f
}

// handle serves a single client connection. It must not touch f.t: it may
// still be running as the test finishes.
func (f *fakePostgresServer) handle(conn net.Conn) {
	defer conn.Close()

	// The first startup message must be an SSLRequest — like Neon, the fake
	// requires TLS.
	backend := pgproto3.NewBackend(conn, conn)
	startup, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := startup.(*pgproto3.SSLRequest); !ok {
		return
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.cert}})
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	backend = pgproto3.NewBackend(tlsConn, tlsConn)
	startup, err = backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	sm, ok := startup.(*pgproto3.StartupMessage)
	if !ok {
		return
	}
	if sm.Parameters["user"] != f.user {
		f.failAuth(backend, fmt.Sprintf("role %q does not exist", sm.Parameters["user"]))
		return
	}

	if err := f.scramAuth(backend); err != nil {
		f.failAuth(backend, "password authentication failed")
		return
	}

	f.mu.Lock()
	f.authOK++
	f.mu.Unlock()

	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: []byte{0, 0, 0, 7}})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return
	}

	for {
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			f.mu.Lock()
			f.lastQuery = m.String
			f.mu.Unlock()

			backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{
				Name:         []byte("ok"),
				DataTypeOID:  25, // text
				DataTypeSize: -1,
				TypeModifier: -1,
			}}})
			backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("yes")}})
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backend.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		default:
			// Ignore anything else (e.g. Sync) and keep serving.
		}
	}
}

// scramAuth runs the server side of a SCRAM-SHA-256 conversation. It returns
// an error if the client fails to prove knowledge of the password.
func (f *fakePostgresServer) scramAuth(backend *pgproto3.Backend) error {
	backend.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
	if err := backend.Flush(); err != nil {
		return err
	}
	if err := backend.SetAuthType(pgproto3.AuthTypeSASL); err != nil {
		return err
	}

	msg, err := backend.Receive()
	if err != nil {
		return err
	}
	initial, ok := msg.(*pgproto3.SASLInitialResponse)
	if !ok {
		return fmt.Errorf("expected SASLInitialResponse, got %T", msg)
	}
	if initial.AuthMechanism != "SCRAM-SHA-256" {
		return fmt.Errorf("unexpected SASL mechanism %q", initial.AuthMechanism)
	}

	conv := f.scramServer.NewConversation()
	serverFirst, err := conv.Step(string(initial.Data))
	if err != nil {
		return err
	}

	backend.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
	if err := backend.Flush(); err != nil {
		return err
	}
	if err := backend.SetAuthType(pgproto3.AuthTypeSASLContinue); err != nil {
		return err
	}

	msg, err = backend.Receive()
	if err != nil {
		return err
	}
	resp, ok := msg.(*pgproto3.SASLResponse)
	if !ok {
		return fmt.Errorf("expected SASLResponse, got %T", msg)
	}

	serverFinal, err := conv.Step(string(resp.Data))
	if err != nil {
		return err
	}
	if !conv.Valid() {
		return errors.New("scram conversation not valid")
	}

	backend.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte(serverFinal)})
	return backend.Flush()
}

// failAuth records the failure and sends a FATAL 28P01 error to the client.
func (f *fakePostgresServer) failAuth(backend *pgproto3.Backend, message string) {
	f.mu.Lock()
	f.authFail++
	f.mu.Unlock()

	backend.Send(&pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     "28P01",
		Message:  message,
	})
	backend.Flush()
}

// TestFakePostgresServerSCRAM exercises the fake end-to-end with pgx's own
// client: the SCRAM verification must accept the real password and reject a
// wrong one.
func TestFakePostgresServerSCRAM(t *testing.T) {
	fake := startFakePostgres(t, "db.test.local", "app_rw", "real-password")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := pgconn.ParseConfig("postgres://app_rw:real-password@" + fake.addr + "/appdb")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.TLSConfig = &tls.Config{ServerName: "db.test.local", RootCAs: fake.certPool}

	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close(ctx)

	results, err := conn.Exec(ctx, "SELECT 1").ReadAll()
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if got := len(results[0].Rows); got != 1 {
		t.Fatalf("got %d rows, want 1", got)
	}
	if got := string(results[0].Rows[0][0]); got != "yes" {
		t.Errorf("row value = %q, want %q", got, "yes")
	}
	if got := fake.queriedLast(); got != "SELECT 1" {
		t.Errorf("lastQuery = %q, want %q", got, "SELECT 1")
	}
	if authOK, _ := fake.counts(); authOK != 1 {
		t.Errorf("authOK = %d, want 1", authOK)
	}

	t.Run("wrong password", func(t *testing.T) {
		cfg, err := pgconn.ParseConfig("postgres://app_rw:wrong-password@" + fake.addr + "/appdb")
		if err != nil {
			t.Fatalf("ParseConfig: %v", err)
		}
		cfg.TLSConfig = &tls.Config{ServerName: "db.test.local", RootCAs: fake.certPool}

		if conn, err := pgconn.ConnectConfig(ctx, cfg); err == nil {
			conn.Close(ctx)
			t.Fatal("Connect with wrong password succeeded, want error")
		}
		if _, authFail := fake.counts(); authFail < 1 {
			t.Errorf("authFail = %d, want >= 1", authFail)
		}
	})
}
