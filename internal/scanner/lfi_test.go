package scanner

import (
	"encoding/base64"
	"testing"
)

func TestConfirmLFIEtcPasswd(t *testing.T) {
	if got := confirmLFI("../../../../etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"); got != "/etc/passwd" {
		t.Fatalf("confirmLFI = %q, want /etc/passwd", got)
	}
}

func TestConfirmLFIPrivateKeyDirectRead(t *testing.T) {
	body := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n-----END OPENSSH PRIVATE KEY-----"
	if got := confirmLFI("../../../../../../../../root/.ssh/id_rsa", body); got != "private key file read" {
		t.Fatalf("confirmLFI = %q, want private key file read", got)
	}
}

func TestConfirmLFIDotenvSecretOnlyWhenPayloadTargetsEnv(t *testing.T) {
	body := "APP_NAME=MyApp\nDB_PASSWORD=supersecret123\nAPP_KEY=base64:abcdef=="
	if got := confirmLFI("../../../../../../../../var/www/.env", body); got != "dotenv secret disclosure" {
		t.Fatalf("confirmLFI = %q, want dotenv secret disclosure", got)
	}
	// Same secret-looking body must NOT fire for an unrelated payload (e.g. plain
	// /etc/passwd traversal) — the dotenv check is gated on the payload targeting
	// .env specifically, not on the body content alone.
	if got := confirmLFI("../../../../etc/passwd", body); got != "" {
		t.Fatalf("confirmLFI = %q, want no finding for a non-.env payload even with secret-looking body", got)
	}
}

func TestConfirmLFIPhpFilterBase64SecretConfigDisclosure(t *testing.T) {
	cfg := "<?php\nreturn ['password' => 'x'];\n// DB_PASSWORD=real-secret-value\n"
	enc := base64.StdEncoding.EncodeToString([]byte(cfg))
	if got := confirmLFI("php://filter/convert.base64-encode/resource=config/database.php", enc); got != "php://filter base64 source disclosure" {
		// The <?php marker already proves source disclosure; the secret-config
		// signature is a backstop for configs with no literal "<?php" (e.g. a
		// .env read through the base64 wrapper), covered by the next case.
		t.Fatalf("confirmLFI = %q, want php://filter base64 source disclosure", got)
	}
}

func TestConfirmLFIPhpFilterBase64EnvWithoutPHPMarker(t *testing.T) {
	env := "APP_ENV=production\nDB_PASSWORD=real-secret-value\nAPP_KEY=base64:xyz=="
	enc := base64.StdEncoding.EncodeToString([]byte(env))
	if got := confirmLFI("php://filter/convert.base64-encode/resource=.env", enc); got != "php://filter base64 secret-config disclosure" {
		t.Fatalf("confirmLFI = %q, want php://filter base64 secret-config disclosure", got)
	}
}

func TestConfirmLFINoFalsePositiveOnUnrelatedBase64(t *testing.T) {
	// Ordinary base64-looking content with no PHP/root/secret signal inside must
	// never be mistaken for a wrapper disclosure.
	enc := base64.StdEncoding.EncodeToString([]byte("just some ordinary encoded payload, nothing sensitive here at all"))
	if got := confirmLFI("php://filter/convert.base64-encode/resource=index.php", enc); got != "" {
		t.Fatalf("confirmLFI = %q, want no finding for unrelated base64 content", got)
	}
}

func TestConfirmLFIEmptyBodyNeverConfirms(t *testing.T) {
	for _, payload := range lfiPayloads {
		if got := confirmLFI(payload, ""); got != "" {
			t.Fatalf("confirmLFI(%q, \"\") = %q, want empty body to never confirm", payload, got)
		}
	}
}
