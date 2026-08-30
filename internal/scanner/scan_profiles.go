package scanner

import "strings"

// Scan profile system (vulnerability-scanner core, section 1). A profile is the
// operator-facing "how hard do we scan" selector — like Acunetix's scan types or
// Burp's audit configs — that resolves to a concrete set of enabled check
// families plus concurrency/budget knobs. Recon is demoted to a lightweight
// DISCOVERY phase in every profile; the emphasis is active vulnerability testing.

// ScanProfileName is the operator-selected profile.
type ScanProfileName string

const (
	ProfileQuick    ScanProfileName = "quick"    // fast, high-signal, low request volume
	ProfileStandard ScanProfileName = "standard" // default balanced audit
	ProfileDeep     ScanProfileName = "deep"     // exhaustive, mutation + race + protocol
	ProfileCustom   ScanProfileName = "custom"   // operator-defined family toggles
)

// CheckFamily groups active checks so a profile can enable/disable them wholesale.
type CheckFamily string

const (
	FamDiscovery CheckFamily = "discovery" // subdomain/port/tech — supporting phase only
	FamCrawl     CheckFamily = "crawl"     // crawling + parameter/form extraction
	FamInjection CheckFamily = "injection" // xss/sqli/cmdi/ssti/nosqli/lfi/xxe
	FamAccess    CheckFamily = "access"    // idor/bola/bfla two-identity authz
	FamSSRF      CheckFamily = "ssrf"      // ssrf + OAST
	FamRedirect  CheckFamily = "redirect"  // open redirect
	FamMisconfig CheckFamily = "misconfig" // headers/cors/cookies/exposure
	FamNuclei    CheckFamily = "nuclei"    // template engine (secondary)
	FamMutation  CheckFamily = "mutation"  // deep mutation escalation ladder
	FamRace      CheckFamily = "race"      // controlled authorization race
	FamProtocol  CheckFamily = "protocol"  // HTTP/1.1 vs HTTP/2 differential
)

// ScanProfile is the resolved, concrete configuration a scan runs with.
type ScanProfile struct {
	Name        ScanProfileName
	Families    map[CheckFamily]bool
	Concurrency int    // worker count for the active job queue
	MaxDepth    int    // crawl depth
	AuthzMode   string // maps to the two-identity engine profile (safe/balanced/deep)
	Destructive bool   // allow gated destructive checks (cross-user DELETE)
	Description string
}

// Enabled reports whether a check family runs under this profile.
func (p ScanProfile) Enabled(f CheckFamily) bool { return p.Families != nil && p.Families[f] }

func families(on ...CheckFamily) map[CheckFamily]bool {
	m := map[CheckFamily]bool{}
	for _, f := range on {
		m[f] = true
	}
	return m
}

// ResolveScanProfile maps a profile name (+ optional custom family list) to a
// concrete ScanProfile. Unknown names fall back to Standard.
func ResolveScanProfile(name string, customFamilies []string) ScanProfile {
	switch ScanProfileName(strings.ToLower(strings.TrimSpace(name))) {
	case ProfileQuick:
		return ScanProfile{
			Name:        ProfileQuick,
			Families:    families(FamDiscovery, FamCrawl, FamInjection, FamRedirect, FamMisconfig),
			Concurrency: 8, MaxDepth: 3, AuthzMode: "safe", Destructive: false,
			Description: "Fast, high-signal pass: crawl + core injection/redirect/misconfig, read-only authz.",
		}
	case ProfileDeep:
		return ScanProfile{
			Name: ProfileDeep,
			Families: families(FamDiscovery, FamCrawl, FamInjection, FamAccess, FamSSRF,
				FamRedirect, FamMisconfig, FamNuclei, FamMutation, FamRace, FamProtocol),
			Concurrency: 24, MaxDepth: 8, AuthzMode: "deep", Destructive: false,
			Description: "Exhaustive audit: full injection + two-identity access control with mutation, race and protocol differential.",
		}
	case ProfileCustom:
		fams := map[CheckFamily]bool{FamCrawl: true} // crawl is always needed for surface
		for _, f := range customFamilies {
			fams[CheckFamily(strings.ToLower(strings.TrimSpace(f)))] = true
		}
		return ScanProfile{Name: ProfileCustom, Families: fams, Concurrency: 16, MaxDepth: 6,
			AuthzMode: "balanced", Destructive: false, Description: "Operator-defined check families."}
	default: // standard
		return ScanProfile{
			Name: ProfileStandard,
			Families: families(FamDiscovery, FamCrawl, FamInjection, FamAccess, FamSSRF,
				FamRedirect, FamMisconfig, FamNuclei),
			Concurrency: 16, MaxDepth: 6, AuthzMode: "balanced", Destructive: false,
			Description: "Balanced audit: full active injection + two-identity access control + templates.",
		}
	}
}

// AuthzProfileFor maps the scan profile to the two-identity authorization engine
// profile, so selecting Deep at the top level also deepens the IDOR/BOLA engine.
func (p ScanProfile) AuthzProfileFor() AuthzProfile { return ParseAuthzProfile(p.AuthzMode) }
