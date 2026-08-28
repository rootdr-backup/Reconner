package api

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"time"
)

// oobTokenRe matches an OAST token as it appears in the DN/path of an inbound
// JNDI/LDAP (or RMI) callback — newXSSToken("rcnoob") = "rcnoob" + 10 hex chars.
var oobTokenRe = regexp.MustCompile(`rcnoob[0-9a-f]{10}`)

// StartLog4ShellListener binds a raw TCP listener that catches NON-HTTP
// out-of-band callbacks — specifically the LDAP/RMI connection a Log4Shell
// (CVE-2021-44228) payload makes back to us. The injected value is
// ${jndi:ldap://<host>:<port>/<token>}; when a vulnerable target's Log4j resolves
// it, its LDAP client connects here and sends the token in the request DN. We
// scan the first bytes for any known token and promote it to a confirmed
// critical finding via the same RecordOOBHit path the HTTP callback uses.
//
// Returns a closer to stop the listener. Best-effort: a bind failure (port in
// use / not permitted) is returned so serve can log it and carry on — the rest
// of the platform is unaffected.
func (h *Handler) StartLog4ShellListener(port int) (io.Closer, error) {
	if port <= 0 {
		port = 1389
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go h.handleRawOOBConn(conn, port)
		}
	}()
	return ln, nil
}

func (h *Handler) handleRawOOBConn(conn net.Conn, port int) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	if n <= 0 {
		return
	}
	srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	seen := map[string]bool{}
	for _, m := range oobTokenRe.FindAll(buf[:n], -1) {
		tok := string(m)
		if seen[tok] {
			continue
		}
		seen[tok] = true
		h.RecordOOBHit(tok, srcIP, "LDAP", "jndi", fmt.Sprintf("JNDI/LDAP :%d", port))
	}
}
