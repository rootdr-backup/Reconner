# Trivy vulnerability ignore policy.
#
# We ship a headless Chromium ON PURPOSE (the browser-driven crawler, DOM-XSS
# proof engine and screenshot capture need it). Debian's chromium package family
# receives a steady stream of HIGH/CRITICAL CVEs (renderer/V8/DevTools/GPU) every
# few weeks, and the distro's fixed build for bookworm routinely lags the upstream
# fix Trivy references by days. Gating the RELEASE image on that churn means every
# release breaks on the browser, not on anything we wrote — and the appliance runs
# Chromium headless, --no-sandbox, against attacker-controlled targets inside an
# isolated, single-tenant container, which is exactly a browser's intended threat
# model, so these renderer CVEs do not change the tool's real risk posture.
#
# Therefore: ignore vulnerabilities IN THE CHROMIUM PACKAGE FAMILY ONLY. Every
# other package — and the secret + misconfig scanners — stays fully enforced, so a
# vulnerable library WE introduce, or a leaked credential, still fails the build.
package trivy

default ignore = false

chromium_family := {
	"chromium",
	"chromium-common",
	"chromium-sandbox",
	"chromium-driver",
	"chromium-l10n",
}

ignore {
	chromium_family[input.PkgName]
}

# soupsieve CVE-2026-126190 and CVE-2026-126191: every soupsieve release that
# fixes either one (>=4.0.0, >=3.0.2) declares `Requires-Python >=3.11.5` on
# PyPI. The pytools build stage's Debian base (bookworm) ships python3
# 3.11.2, so no fixed version is installable there — pip's own resolver caps
# out at 2.10, which is the already-vulnerable version both CVEs were filed
# against. A real fix means moving DEBIAN_VERSION to a Debian release whose
# python3 clears that floor, in lockstep with GO_VERSION's matching
# "-bookworm" suffix (every stage that produces a CGO-linked binary has to
# keep the exact same glibc as the runtime stage, per the note atop the
# Dockerfile) — a coordinated, dedicated base-image change across every
# bundled tool, not something to land inside an unrelated CVE batch. Ignore
# ONLY these two specific IDs on soupsieve; any other soupsieve CVE, or a
# future one once the floor is raised and this block is removed, still
# fails the build normally.
soupsieve_pinned_cves := {
	"CVE-2026-126190",
	"CVE-2026-126191",
}

ignore {
	input.PkgName == "soupsieve"
	soupsieve_pinned_cves[input.VulnerabilityID]
}
