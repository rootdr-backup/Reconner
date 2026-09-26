package scanner

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

func TestNativeConnectScanFindsOnlyOpenLocalPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	closed := port + 1
	got, err := nativeConnectScan(context.Background(), []string{"127.0.0.1"}, []int{closed, port}, 2, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != "127.0.0.1" || got[0].Port != port {
		t.Fatalf("open=%+v, want only 127.0.0.1:%d", got, port)
	}
}

func TestNmapXMLServiceAndOSParsing(t *testing.T) {
	raw := `<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/><hostnames><hostname name="router.test"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25" tunnel="ssl"/></port></ports><os><osmatch name="Linux 5.x" accuracy="95"/></os></host></nmaprun>`
	var parsed nmapRun
	if err := xml.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Hosts) != 1 || len(parsed.Hosts[0].Ports) != 1 {
		t.Fatalf("parsed=%+v", parsed)
	}
	host := parsed.Hosts[0]
	if host.Addresses[0].Addr != "192.0.2.5" || host.Ports[0].Service.Product != "nginx" || host.OS[0].Name != "Linux 5.x" {
		t.Fatalf("unexpected XML mapping: %+v", host)
	}
}

func TestBasicAuthAuditRequiresChallengeAndStableSuccess(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == want {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="local-test"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	db, targetID := testDB(t)
	defer db.Close()
	_, err := db.Exec(`INSERT INTO network_services(id,target_id,ip,port,protocol,is_web,web_url,web_status) VALUES(?,?,?,?,'tcp',1,?,401)`, uuid.New().String(), targetID, u.Hostname(), port, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	s := NewNetworkScanner(db, nil, &config.Config{}, nil)
	if err := s.RunBasicAuth(context.Background(), targetID, "127.0.0.1", func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := db.QueryRow(`SELECT payload FROM vuln_findings WHERE target_id=? AND type='http_basic_weak_credentials'`, targetID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if payload != "admin:admin" {
		t.Fatalf("payload=%q", payload)
	}
}

func TestBasicAuthDefaultCorpusHasOneThousandUniquePasswords(t *testing.T) {
	passwords := defaultBasicAuthPasswords()
	if len(passwords) != 1000 {
		t.Fatalf("password count=%d, want 1000", len(passwords))
	}
	seen := map[string]bool{}
	for _, password := range passwords {
		if password == "" || seen[password] {
			t.Fatalf("invalid/duplicate password %q", password)
		}
		seen[password] = true
	}
}
