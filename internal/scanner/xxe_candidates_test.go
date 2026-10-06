package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestXXECandidateEndpointsIncludesJSONRESTEndpoints proves the fix for a real
// routing gap: a plain JSON/REST-shaped service (no "xml"/"soap"/etc signal in
// its URL or content-type) used to be hard-excluded from candidateEndpoints
// entirely, even though many backend frameworks pick their body parser from
// the REQUEST's Content-Type header (which Reconner controls), not from the
// API's documented/observed shape.
func TestXXECandidateEndpointsIncludesJSONRESTEndpoints(t *testing.T) {
	db, targetID := newV3ScannerDB(t)
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,content_type) VALUES (?,?,?,200,'application/json')`,
		uuid.New().String(), targetID, "https://x.test/api/widgets"); err != nil {
		t.Fatal(err)
	}

	s := &XXEScanner{db: db}
	eps := s.candidateEndpoints(context.Background(), targetID)
	found := false
	for _, ep := range eps {
		if ep.URL == "https://x.test/api/widgets" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a plain JSON/REST endpoint to be a candidate, got %+v", eps)
	}
}

// TestXXECandidateEndpointsMarksUploadAndSVGAsMultipart proves an "upload"/
// ".svg"-shaped URL produces BOTH the original raw-POST candidate AND an
// additional Multipart=true candidate — additive coverage, not a replacement.
func TestXXECandidateEndpointsMarksUploadAndSVGAsMultipart(t *testing.T) {
	db, targetID := newV3ScannerDB(t)
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code) VALUES (?,?,?,200)`,
		uuid.New().String(), targetID, "https://x.test/avatar/upload"); err != nil {
		t.Fatal(err)
	}

	s := &XXEScanner{db: db}
	eps := s.candidateEndpoints(context.Background(), targetID)
	var sawRaw, sawMultipart bool
	for _, ep := range eps {
		if ep.URL != "https://x.test/avatar/upload" {
			continue
		}
		if ep.Multipart {
			sawMultipart = true
		} else {
			sawRaw = true
		}
	}
	if !sawRaw {
		t.Error("expected the original raw-POST candidate to still be present")
	}
	if !sawMultipart {
		t.Error("expected an additional Multipart candidate for the upload-shaped URL")
	}
}

// TestSendXMLMultipartDeliversPayloadAsFilePart proves sendXMLMultipart
// actually builds a real multipart/form-data request with the XXE payload
// inside a file part (not a bare POST body) — the shape an upload endpoint
// needs to ever hand the content to its XML parser.
func TestSendXMLMultipartDeliversPayloadAsFilePart(t *testing.T) {
	withLoopbackAllowed(t)
	const marker = "recon-xxe-multipart-marker"
	var sawMultipart, sawMarkerInFilePart bool
	mux := http.NewServeMux()
	mux.HandleFunc("/upload.svg", func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sawMultipart = true
		for {
			part, perr := mr.NextPart()
			if perr != nil {
				break
			}
			buf := make([]byte, 4096)
			n, _ := part.Read(buf)
			if strings.Contains(string(buf[:n]), marker) {
				sawMarkerInFilePart = true
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &XXEScanner{}
	ep := xxeEndpoint{URL: srv.URL + "/upload.svg", Method: "POST", ContentType: "application/xml", Multipart: true}
	status, _ := s.sendXMLMultipart(context.Background(), ep, "<root>"+marker+"</root>", nil)
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if !sawMultipart {
		t.Error("expected a multipart/form-data request, got something else")
	}
	if !sawMarkerInFilePart {
		t.Error("expected the payload marker to be readable from a file part")
	}
}

// TestXXEConfirmsUploadOnlyParsedViaMultipart drives the real XXEScanner
// end-to-end against a mock server that ONLY parses XML (and leaks the
// passwd signature) when the body arrives as a genuine multipart file
// upload — a raw POST body is rejected, exactly the real-world shape this fix
// targets. Before the fix, candidateEndpoints sent only a raw POST to this
// URL and the vulnerability was never found.
func TestXXEConfirmsUploadOnlyParsedViaMultipart(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/avatar/upload", func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "raw body uploads are not supported")
			return
		}
		for {
			part, perr := mr.NextPart()
			if perr != nil {
				break
			}
			buf := make([]byte, 8192)
			n, _ := part.Read(buf)
			body := string(buf[:n])
			if strings.Contains(body, "SYSTEM") && strings.Contains(body, "file:///etc/passwd") {
				fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
				return
			}
		}
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code) VALUES (?,?,?,200)`,
		uuid.New().String(), targetID, srv.URL+"/avatar/upload"); err != nil {
		t.Fatal(err)
	}

	s := NewXXEScanner(db, nil, nil, nil, nil)
	if err := s.Run(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	if got := v3FindingCount(t, db, targetID, "xxe", "/avatar/upload"); got != 1 {
		t.Fatalf("multipart-only XXE findings=%d, want 1", got)
	}
}
