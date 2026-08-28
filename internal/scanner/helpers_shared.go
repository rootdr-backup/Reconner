package scanner

// commonServicePorts maps well-known ports to a service label (used by the
// Shodan intel module to name a port when the provider gives no product).
// Previously lived in the now-retired portscan module.
var commonServicePorts = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
	143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
	5432: "postgres", 5601: "kibana", 5900: "vnc", 6379: "redis",
	8080: "http-alt", 8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
	9300: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

// truncate shortens s to at most n bytes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
