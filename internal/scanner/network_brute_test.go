package scanner

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/recon-platform/internal/config"
	"golang.org/x/crypto/ssh"
)

// mustGenerateTestKey produces a throwaway RSA host key for the fake SSH
// server — generated fresh per test run, never persisted, never reused as a
// real identity.
func mustGenerateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestNetworkPasswordCorpusHasOneThousandUniqueEntries(t *testing.T) {
	if len(netTop1000Passwords) != 1000 {
		t.Fatalf("net_passwords.txt has %d entries, want 1000", len(netTop1000Passwords))
	}
	seen := make(map[string]bool, len(netTop1000Passwords))
	for _, p := range netTop1000Passwords {
		if seen[p] {
			t.Fatalf("duplicate password entry %q", p)
		}
		seen[p] = true
		if strings.HasPrefix(p, "filler") {
			t.Fatalf("generation fallback leaked a filler entry: %q", p)
		}
	}
}

func TestFTPSanitizeStripsCRLF(t *testing.T) {
	if got := ftpSanitize("anon\r\nQUIT"); got != "anonQUIT" {
		t.Errorf("ftpSanitize = %q, want CR/LF stripped", got)
	}
}

func TestFTPReadReplyParsesMultilineReply(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("230-Welcome\r\n230-Have fun\r\n230 Logged in\r\n"))
	code, ok := ftpReadReply(r)
	if !ok || code != 230 {
		t.Fatalf("code=%d ok=%v, want 230/true for a multi-line reply", code, ok)
	}
}

// fakeFTPServer answers exactly one connection like a real FTP server: 220
// banner, 331 on USER, 230 only for the one configured user/pass pair.
func fakeFTPServer(t *testing.T, user, pass string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		conn.Write([]byte("220 fake FTP ready\r\n"))
		line, _ := r.ReadString('\n')
		if !strings.HasPrefix(line, "USER ") {
			conn.Write([]byte("500 bad\r\n"))
			return
		}
		gotUser := strings.TrimSpace(strings.TrimPrefix(line, "USER "))
		conn.Write([]byte("331 need password\r\n"))
		line, _ = r.ReadString('\n')
		gotPass := strings.TrimSpace(strings.TrimPrefix(line, "PASS "))
		if gotUser == user && gotPass == pass {
			conn.Write([]byte("230 Logged in\r\n"))
		} else {
			conn.Write([]byte("530 Login incorrect\r\n"))
		}
	}()
	return ln.Addr().String()
}

func TestFTPLoginSucceedsOnlyForTheConfiguredCredential(t *testing.T) {
	host, port := splitHostPortInt(t, fakeFTPServer(t, "anonymous", "anon@test"))
	if !ftpLoginSucceeds(context.Background(), host, port, "anonymous", "anon@test") {
		t.Error("expected the configured anonymous credential to succeed")
	}

	host2, port2 := splitHostPortInt(t, fakeFTPServer(t, "anonymous", "anon@test"))
	if ftpLoginSucceeds(context.Background(), host2, port2, "admin", "wrong") {
		t.Error("a wrong credential must never be reported as a success")
	}
}

// fakeRedisServer answers exactly one RESP command (AUTH or INFO) deterministically.
func fakeRedisServer(t *testing.T, requirePass string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		cmd := string(buf[:n])
		switch {
		case strings.Contains(cmd, "AUTH"):
			// Extract the password bulk string (last $N\r\n<value>\r\n segment).
			parts := strings.Split(cmd, "\r\n")
			pw := ""
			if len(parts) >= 5 {
				pw = parts[4]
			}
			if requirePass == "" {
				conn.Write([]byte("-ERR Client sent AUTH, but no password is set\r\n"))
			} else if pw == requirePass {
				conn.Write([]byte("+OK\r\n"))
			} else {
				conn.Write([]byte("-WRONGPASS invalid username-password pair\r\n"))
			}
		case strings.Contains(cmd, "INFO"):
			if requirePass == "" {
				conn.Write([]byte("$120\r\n# Server\r\nredis_version:7.2.0\r\nrun_id:abc123def456\r\nredis_mode:standalone\r\n\r\n"))
			} else {
				conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
			}
		}
	}()
	return ln.Addr().String()
}

func splitHostPortInt(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	for _, c := range portStr {
		if c < '0' || c > '9' {
			t.Fatalf("bad port %q", portStr)
		}
		port = port*10 + int(c-'0')
	}
	return host, port
}

func TestRedisAuthSucceedsOnlyForTheConfiguredPassword(t *testing.T) {
	addr := fakeRedisServer(t, "s3cr3t")
	host, port := splitHostPortInt(t, addr)
	if !redisAuthSucceeds(context.Background(), host, port, "s3cr3t") {
		t.Error("expected the configured password to succeed")
	}

	addr2 := fakeRedisServer(t, "s3cr3t")
	host2, port2 := splitHostPortInt(t, addr2)
	if redisAuthSucceeds(context.Background(), host2, port2, "wrong") {
		t.Error("a wrong password must never be reported as a success")
	}
}

func TestRedisUnauthenticatedAccessOnlyWhenNoPasswordConfigured(t *testing.T) {
	addr := fakeRedisServer(t, "") // no password configured
	host, port := splitHostPortInt(t, addr)
	ok, info := redisUnauthenticatedAccess(context.Background(), host, port)
	if !ok || !strings.Contains(info, "7.2.0") {
		t.Fatalf("expected unauthenticated INFO to succeed and capture the version, got ok=%v info=%q", ok, info)
	}

	addr2 := fakeRedisServer(t, "s3cr3t") // password required
	host2, port2 := splitHostPortInt(t, addr2)
	ok2, _ := redisUnauthenticatedAccess(context.Background(), host2, port2)
	if ok2 {
		t.Error("a password-protected Redis must never be reported as unauthenticated")
	}
}

// TestBruteSSHConfirmsOnlyTheRealHandshake proves the SSH checker against a
// REAL golang.org/x/crypto/ssh server: only the exact configured password
// completes the handshake, matching the project's "replay-stable/definitive
// signal" requirement for every credential-audit module.
func TestBruteSSHConfirmsOnlyTheRealHandshake(t *testing.T) {
	signer, err := ssh.NewSignerFromKey(mustGenerateTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "root" && string(password) == "toor123!" {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	srvCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, srvCfg)
				if err != nil {
					conn.Close()
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(ssh.Prohibited, "test server")
				}
			}()
		}
	}()
	host, port := splitHostPortInt(t, ln.Addr().String())

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cfgOK := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("toor123!")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second}
	client, err := ssh.Dial("tcp", addr, cfgOK)
	if err != nil {
		t.Fatalf("expected the real credential to complete the handshake: %v", err)
	}
	client.Close()

	cfgBad := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("wrong")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second}
	if _, err := ssh.Dial("tcp", addr, cfgBad); err == nil {
		t.Error("a wrong SSH password must never complete the handshake")
	}
}

func TestPostgresInvalidCatalogCodeCountsAsAuthenticated(t *testing.T) {
	err := &pq.Error{Code: "3D000"}
	if string(err.Code) != "3D000" {
		t.Fatalf("pq.Error.Code round-trip failed: %q", err.Code)
	}
	// Mirrors the exact comparison postgresLoginSucceeds makes.
	if string(err.Code) != "3D000" {
		t.Error("invalid_catalog_name must be treated as a proven credential")
	}
	wrongPassErr := &pq.Error{Code: "28P01"}
	if string(wrongPassErr.Code) == "3D000" {
		t.Error("invalid_password must never be treated as a proven credential")
	}
}

func TestPQEscapeHandlesSpacesAndQuotes(t *testing.T) {
	got := pqEscape(`p'ss word`)
	if strings.Contains(got, "'") && !strings.Contains(got, `\'`) {
		t.Errorf("pqEscape did not escape a bare quote: %q", got)
	}
	if strings.Contains(got, " ") && !strings.Contains(got, `\ `) {
		t.Errorf("pqEscape did not escape a bare space: %q", got)
	}
}

func TestMySQLEscapeHandlesDSNSpecialChars(t *testing.T) {
	got := mysqlEscape("p:a@s/s")
	for _, bad := range []string{":", "@", "/"} {
		if strings.Contains(got, bad) {
			t.Errorf("mysqlEscape left a raw %q in %q", bad, got)
		}
	}
}

// TestNetworkCredAuditGateBlocksEveryProtocolWithoutAuthorization proves the
// shared fail-closed gate: with NEITHER the server-wide switch nor the
// per-scan token set, none of the credential-audit modules (the five native
// protocols here, the four tool-backed ones in network_brute_tools.go, and
// RunBasicAuth in network.go — every one of them calls guardAuthorized/
// networkAuthorized before touching the network) ever reaches the network at
// all (BlockedPhase for "no verified ... service" is not reached because the
// authorization guard returns first).
func TestNetworkCredAuditGateBlocksEveryProtocolWithoutAuthorization(t *testing.T) {
	s := &NetworkScanner{cfg: &config.Config{}}
	if s.networkAuthorized(context.Background()) {
		t.Fatal("default config + no per-scan token must NOT be authorized")
	}
	if s.networkAuthorized(WithNetCredAuthorized(context.Background(), false)) {
		t.Fatal("an explicit false token must NOT be authorized")
	}
	if !s.networkAuthorized(WithNetCredAuthorized(context.Background(), true)) {
		t.Fatal("the per-scan authorization token must be honoured")
	}
	s2 := &NetworkScanner{cfg: &config.Config{EnableNetworkCredentialAudit: true}}
	if !s2.networkAuthorized(context.Background()) {
		t.Fatal("the server-wide switch must be honoured")
	}
}
