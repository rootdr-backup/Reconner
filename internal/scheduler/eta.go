package scheduler

import "time"

// Scan ETA estimation. Modules have very different typical durations, so a flat
// "elapsed / percent-done" is misleading (a scan can sit 90% through the module
// list but be about to hit the two slowest modules, nuclei + sqli). Instead we keep
// a per-module baseline estimate and, once some modules have finished, CALIBRATE it
// to THIS target by scaling the baselines by (actual elapsed / baseline for the
// modules already done). The result is a per-module ETA and a whole-scan ETA that
// adapt to a small vs. huge target.

// moduleETASeconds is the baseline wall-clock estimate for each module on a
// typical target. Only the RATIOS matter — the live scale factor absorbs absolute
// speed differences between targets/hosts.
var moduleETASeconds = map[string]int{
	"subdomain_enum": 180, "http_probe": 40, "js_analysis": 120, "js_endpoints": 60,
	"param_discovery": 240, "timemachine": 60, "param_reflection": 180, "paramfuzz": 120,
	"dir_discovery": 180, "backup_discovery": 90, "open_redirect": 40, "nuclei": 600,
	"xss": 300, "dast": 180, "vuln_scan": 60, "sqli": 300, "ssrf": 90, "lfi": 60,
	"ssti": 60, "cmdi": 120, "nosqli": 60, "cache_poison": 40, "xxe": 60, "jwt": 30,
	"oast": 60, "passive": 60, "takeover": 30, "exposure": 90, "intel": 60,
	"origin_ip": 40, "shodan": 30, "race": 40, "smuggling": 40, "ato": 60,
	"verify": 60, "monitor": 20,
}

func moduleEst(m string) int {
	if v, ok := moduleETASeconds[m]; ok {
		return v
	}
	return 60
}

// scanETA returns the estimated seconds remaining for the WHOLE scan and for the
// CURRENT module, given the full module list, the index of the module just started,
// and how long the scan has been running. The baseline is calibrated by the ratio of
// real elapsed time to the baseline for the modules already completed.
func scanETA(modules []string, currentIdx int, elapsed time.Duration) (totalRemaining, currentRemaining int) {
	if currentIdx < 0 || currentIdx >= len(modules) {
		return 0, 0
	}
	doneEst := 0
	for i := 0; i < currentIdx; i++ {
		doneEst += moduleEst(modules[i])
	}
	remainingEst := 0
	for i := currentIdx; i < len(modules); i++ {
		remainingEst += moduleEst(modules[i])
	}
	scale := 1.0
	if doneEst > 0 && elapsed > 0 {
		scale = elapsed.Seconds() / float64(doneEst)
		if scale < 0.25 {
			scale = 0.25
		}
		if scale > 4 {
			scale = 4
		}
	}
	totalRemaining = int(scale * float64(remainingEst))
	currentRemaining = int(scale * float64(moduleEst(modules[currentIdx])))
	return totalRemaining, currentRemaining
}
