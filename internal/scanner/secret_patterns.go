package scanner

import "regexp"

// This file adds a large, curated, HIGH-SIGNAL set of provider-specific secret
// detectors (trufflehog-style). Every pattern here keys off a distinctive,
// vendor-assigned prefix/shape (ghp_, glpat-, sk_live_, dop_v1_, …) so matches
// are real credentials, not random strings — that keeps false positives near
// zero while covering ~50 providers the generic api_key/secret regexes miss.
// They are appended to jsPatterns and scanned against every JS/HTML body.
var extraSecretPatterns = []jsPattern{
	// ── Source control / package registries ─────────────────────────────────
	{"github_pat", "critical", regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b`)},
	{"github_oauth", "critical", regexp.MustCompile(`\bgho_[0-9A-Za-z]{36}\b`)},
	{"github_app_token", "critical", regexp.MustCompile(`\b(?:ghu|ghs)_[0-9A-Za-z]{36}\b`)},
	{"github_refresh", "high", regexp.MustCompile(`\bghr_[0-9A-Za-z]{36}\b`)},
	{"github_fine_grained", "critical", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{82}\b`)},
	{"gitlab_pat", "critical", regexp.MustCompile(`\bglpat-[0-9A-Za-z_\-]{20}\b`)},
	{"npm_token", "high", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`)},
	{"pypi_token", "critical", regexp.MustCompile(`\bpypi-AgEIcHlwaS[0-9A-Za-z_\-]{50,}\b`)},
	{"rubygems", "high", regexp.MustCompile(`\brubygems_[0-9a-f]{48}\b`)},
	{"docker_hub_pat", "high", regexp.MustCompile(`\bdckr_pat_[0-9A-Za-z_\-]{27,}\b`)},

	// ── Cloud providers ─────────────────────────────────────────────────────
	{"aws_access_key", "critical", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{"gcp_api_key", "high", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"gcp_service_account", "critical", regexp.MustCompile(`"type":\s*"service_account"`)},
	{"gcp_oauth", "high", regexp.MustCompile(`\bya29\.[0-9A-Za-z_\-]{50,}\b`)},
	{"digitalocean_pat", "critical", regexp.MustCompile(`\bdop_v1_[0-9a-f]{64}\b`)},
	{"digitalocean_oauth", "critical", regexp.MustCompile(`\bdoo_v1_[0-9a-f]{64}\b`)},
	{"heroku_api_key", "high", regexp.MustCompile(`(?i)heroku[a-z0-9_\- ]{0,20}[:=]\s*["'` + "`" + `]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)},
	{"azure_storage_key", "critical", regexp.MustCompile(`(?i)AccountKey=[0-9A-Za-z+/]{86}==`)},
	{"cloudflare_api_token", "high", regexp.MustCompile(`(?i)cloudflare[a-z0-9_\- ]{0,20}[:=]\s*["'` + "`" + `]?[A-Za-z0-9_\-]{40}`)},

	// ── Payments ────────────────────────────────────────────────────────────
	{"stripe_secret", "critical", regexp.MustCompile(`\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b`)},
	{"stripe_restricted", "high", regexp.MustCompile(`\bsk_test_[0-9a-zA-Z]{24,99}\b`)},
	{"square_access", "critical", regexp.MustCompile(`\b(?:sq0atp|sq0csp|EAAA)[0-9A-Za-z_\-]{22,60}\b`)},
	{"paypal_braintree", "high", regexp.MustCompile(`\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b`)},
	{"shopify_token", "critical", regexp.MustCompile(`\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b`)},

	// ── Comms / messaging ───────────────────────────────────────────────────
	{"slack_token", "high", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b`)},
	{"slack_webhook", "high", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z_\-]{8,}/B[0-9A-Za-z_\-]{8,}/[0-9A-Za-z_\-]{24,}`)},
	{"discord_webhook", "medium", regexp.MustCompile(`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_\-]{60,}`)},
	{"discord_bot_token", "high", regexp.MustCompile(`\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b`)},
	{"telegram_bot_token", "high", regexp.MustCompile(`\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}\b`)},
	{"twilio_account_sid", "high", regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`)},
	{"twilio_api_key", "high", regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)},
	{"sendgrid", "critical", regexp.MustCompile(`\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b`)},
	{"mailgun", "high", regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`)},
	{"mailchimp", "high", regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`)},
	{"postmark", "high", regexp.MustCompile(`(?i)postmark[a-z0-9_\- ]{0,20}[:=]\s*["'` + "`" + `]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)},

	// ── AI / dev platforms ──────────────────────────────────────────────────
	{"openai_key", "critical", regexp.MustCompile(`\bsk-(?:proj-)?[0-9A-Za-z_\-]{20,}T3BlbkFJ[0-9A-Za-z_\-]{20,}\b`)},
	{"anthropic_key", "critical", regexp.MustCompile(`\bsk-ant-[0-9A-Za-z_\-]{20,}\b`)},
	{"huggingface", "high", regexp.MustCompile(`\bhf_[0-9A-Za-z]{34}\b`)},
	{"algolia_admin", "high", regexp.MustCompile(`(?i)algolia[a-z0-9_\- ]{0,20}[:=]\s*["'` + "`" + `]?[0-9a-zA-Z]{32}`)},
	{"datadog_api", "high", regexp.MustCompile(`(?i)datadog[a-z0-9_\- ]{0,20}[:=]\s*["'` + "`" + `]?[0-9a-f]{32}`)},
	{"newrelic", "high", regexp.MustCompile(`\bNRAK-[0-9A-Z]{27}\b`)},
	{"pagerduty", "medium", regexp.MustCompile(`\b[uy]\+[0-9A-Za-z_\-]{19}\b`)},
	{"grafana_token", "high", regexp.MustCompile(`\bglc_[0-9A-Za-z_\-+/=]{32,}\b`)},
	{"postman_key", "high", regexp.MustCompile(`\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b`)},
	{"databricks", "high", regexp.MustCompile(`\bdapi[0-9a-f]{32}\b`)},
	{"linear_key", "high", regexp.MustCompile(`\blin_api_[0-9A-Za-z]{40}\b`)},
	{"figma_token", "medium", regexp.MustCompile(`\bfigd_[0-9A-Za-z_\-]{40,}\b`)},

	// ── Generic but high-confidence structural secrets ──────────────────────
	{"jwt", "high", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
	{"private_key_block", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{"basic_auth_url", "high", regexp.MustCompile(`(?i)\b(?:https?|ftp)://[a-z0-9._%\-]+:[^\s:@"'` + "`" + `/]{3,}@[a-z0-9.\-]+`)},
	{"generic_bearer", "medium", regexp.MustCompile(`(?i)authorization["'` + "`" + `\s]*[:=]["'` + "`" + `\s]*bearer\s+[A-Za-z0-9_\-\.=]{20,}`)},
}

func init() {
	jsPatterns = append(jsPatterns, extraSecretPatterns...)
}
