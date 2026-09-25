package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

type uploadLab struct {
	mu     sync.Mutex
	server *httptest.Server
	files  map[string][]byte
	config bool
}

func newUploadLab(t *testing.T, mode string, callback func(string)) *uploadLab {
	t.Helper()
	lab := &uploadLab{files: map[string][]byte{}}
	lab.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			lab.serveStored(w, r)
			return
		}
		filename, mime, body := readLabUpload(r)
		vulnerable := strings.HasPrefix(r.URL.Path, "/vuln/")
		accepted := vulnerable && lab.accept(mode, filename, mime, body)
		if !accepted {
			// Patched sibling accepts a real image but serves it as inert content.
			if strings.EqualFold(path.Ext(filename), ".jpg") && bytes.HasPrefix(body, []byte("\xff\xd8\xff")) {
				stored := "/safe-files/" + path.Base(filename)
				lab.put(stored, body)
				writeUploadJSON(w, lab.server.URL+stored)
				return
			}
			http.Error(w, "rejected by patched upload policy", http.StatusUnsupportedMediaType)
			return
		}
		stored := "/uploads/" + path.Base(filename)
		if mode == "rename" {
			stored = "/uploads/server-generated-7f3.bin"
		}
		if mode == "zip" {
			for name, content := range unzipLab(body) {
				if strings.HasPrefix(name, "../../") {
					lab.put("/"+path.Base(name), content)
				}
			}
		}
		if mode == "tar" {
			for name, content := range untarGzipLab(body) {
				if strings.HasPrefix(name, "../../") {
					lab.put("/"+path.Base(name), content)
				}
			}
		}
		if mode == "config" && (filename == ".htaccess" || filename == "web.config") {
			lab.mu.Lock()
			lab.config = true
			lab.mu.Unlock()
		}
		lab.put(stored, body)
		if callback != nil && (mode == "oob" || mode == "ooxml") {
			if cb := callbackURLFromUpload(body); cb != "" {
				callback(cb)
			}
		}
		writeUploadJSON(w, lab.server.URL+stored)
	}))
	t.Cleanup(lab.server.Close)
	return lab
}

func (l *uploadLab) accept(mode, filename, mime string, body []byte) bool {
	switch mode {
	case "blacklist":
		return strings.EqualFold(path.Ext(filename), ".phtml")
	case "whitelist":
		return strings.HasSuffix(strings.ToLower(filename), ".php.jpg")
	case "mime":
		return strings.HasSuffix(strings.ToLower(filename), ".php") && mime == "image/jpeg"
	case "polyglot":
		return bytes.HasPrefix(body, []byte("GIF89a")) && bytes.Contains(body, []byte("<?php"))
	case "rename":
		return filename == "recon-rename.php"
	case "svg":
		return strings.HasSuffix(filename, ".svg") && bytes.Contains(body, []byte("document.title"))
	case "oob":
		return (strings.HasSuffix(filename, ".svg") || strings.HasSuffix(filename, ".mvg")) && callbackURLFromUpload(body) != ""
	case "ooxml":
		return (strings.HasSuffix(filename, ".docx") || strings.HasSuffix(filename, ".xlsx") || strings.HasSuffix(filename, ".pptx")) && callbackURLFromUpload(body) != ""
	case "zip":
		for name := range unzipLab(body) {
			if strings.HasPrefix(name, "../../") {
				return true
			}
		}
		return false
	case "tar":
		for name := range untarGzipLab(body) {
			if strings.HasPrefix(name, "../../") {
				return true
			}
		}
		return false
	case "config":
		if filename == ".htaccess" || filename == "web.config" {
			return true
		}
		l.mu.Lock()
		enabled := l.config
		l.mu.Unlock()
		return enabled && strings.HasSuffix(filename, ".rcn")
	}
	return false
}

func (l *uploadLab) put(name string, body []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.files[name] = append([]byte(nil), body...)
}

var quotedMarkerPart = regexp.MustCompile(`['"]([A-Za-z0-9]+)['"]`)

func executedLabMarker(body []byte) string {
	matches := quotedMarkerPart.FindAllSubmatch(body, -1)
	for i := 0; i+1 < len(matches); i++ {
		if strings.HasPrefix(string(matches[i][1]), "rcnup") || strings.HasPrefix(string(matches[i][1]), "rcnconf") {
			return string(matches[i][1]) + string(matches[i+1][1])
		}
	}
	return ""
}

func (l *uploadLab) serveStored(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	body, ok := l.files[r.URL.Path]
	configured := l.config
	l.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if marker := executedLabMarker(body); marker != "" && (strings.Contains(string(body), "<?php") || strings.Contains(string(body), "out.print") || strings.Contains(string(body), "string.Concat") || configured) {
		fmt.Fprint(w, marker)
		return
	}
	if strings.HasSuffix(r.URL.Path, ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
	}
	_, _ = w.Write(body)
}

func readLabUpload(r *http.Request) (string, string, []byte) {
	if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		_ = r.ParseMultipartForm(2 << 20)
		for _, headers := range r.MultipartForm.File {
			if len(headers) == 0 {
				continue
			}
			f, _ := headers[0].Open()
			defer f.Close()
			body, _ := io.ReadAll(f)
			return headers[0].Filename, headers[0].Header.Get("Content-Type"), body
		}
	}
	var root map[string]any
	_ = json.NewDecoder(r.Body).Decode(&root)
	for _, v := range root {
		if list, ok := v.([]any); ok && len(list) > 0 {
			v = list[0]
		}
		if obj, ok := v.(map[string]any); ok {
			data, _ := base64.StdEncoding.DecodeString(fmt.Sprint(obj["data"]))
			return fmt.Sprint(obj["filename"]), fmt.Sprint(obj["content_type"]), data
		}
	}
	return "", "", nil
}

func writeUploadJSON(w http.ResponseWriter, publicURL string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"url": publicURL})
}

func unzipLab(body []byte) map[string][]byte {
	out := map[string][]byte{}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return out
	}
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(r)
		r.Close()
		out[f.Name] = data
	}
	return out
}

func untarGzipLab(body []byte) map[string][]byte {
	out := map[string][]byte{}
	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return out
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out
		}
		data, _ := io.ReadAll(tr)
		out[h.Name] = data
	}
	return out
}

var callbackURLRE = regexp.MustCompile(`https?://[^\s"'<>]+/oob/[a-zA-Z0-9]+`)

func callbackURLFromUpload(body []byte) string {
	if match := callbackURLRE.Find(body); match != nil {
		return string(match)
	}
	for _, content := range unzipLab(body) {
		if match := callbackURLRE.Find(content); match != nil {
			return string(match)
		}
	}
	return ""
}

func newFileUploadTestScanner(t *testing.T) (*FileUploadScanner, *database.DB, string) {
	t.Helper()
	withLoopbackAllowed(t)
	db, targetID := newV3ScannerDB(t)
	s := NewFileUploadScanner(db, nil, &config.Config{}, nil, nil)
	return s, db, targetID
}

func multipartPoint(rawURL string) insertionPoint {
	return insertionPoint{URL: rawURL, Param: "file", Method: "POST", ContentType: "multipart/form-data", Location: "body", Siblings: map[string]string{"csrf": "local-test"}}
}

func chooseAttempt(t *testing.T, attempts []fileUploadAttempt, subtype string, match func(fileUploadAttempt) bool) fileUploadAttempt {
	t.Helper()
	for _, a := range attempts {
		if a.subtype == subtype && (match == nil || match(a)) {
			return a
		}
	}
	t.Fatalf("attempt %s not found", subtype)
	return fileUploadAttempt{}
}

func runLabAttempt(t *testing.T, s *FileUploadScanner, db *database.DB, targetID string, ip insertionPoint, a fileUploadAttempt) int {
	t.Helper()
	result, err := s.upload(context.Background(), ip, nil, a)
	if err != nil || result.status < 200 || result.status >= 400 {
		return 0
	}
	var proofURL, evidence string
	switch a.proof {
	case proofExecution:
		proofURL, evidence = s.verifyExecution(context.Background(), ip, nil, a, result.urls)
	case proofStoredSVG:
		proofURL, evidence = s.verifySVG(context.Background(), nil, a, result.urls)
	case proofZipSlip:
		proofURL, evidence = s.verifyZipSlip(context.Background(), ip, nil, a, result.urls)
	case proofConfigEffect:
		proofURL, evidence = s.verifyConfigEffect(context.Background(), ip, nil, a)
	case proofOOB:
		proofURL, evidence = s.verifyOOB(context.Background(), a)
	}
	if evidence == "" {
		return 0
	}
	if a.proof == proofOOB {
		if s.storeOOBFinding(context.Background(), targetID, ip, a, evidence, result.item) {
			return 1
		}
	} else if s.storeFinding(context.Background(), targetID, ip, a, proofURL, evidence, result.item) {
		return 1
	}
	return 0
}

func TestFileUploadBypassMatrixUsesDangerousRetrievalProof(t *testing.T) {
	cases := []struct {
		name, mode, subtype string
		match               func(fileUploadAttempt) bool
	}{
		{"extension blacklist", "blacklist", "extension_blacklist", func(a fileUploadAttempt) bool { return strings.HasSuffix(a.filename, ".phtml") }},
		{"extension whitelist", "whitelist", "extension_whitelist", func(a fileUploadAttempt) bool { return strings.HasSuffix(a.filename, ".php.jpg") }},
		{"content type mismatch", "mime", "content_type_mismatch", func(a fileUploadAttempt) bool { return a.filename == "recon.php" }},
		{"magic byte polyglot", "polyglot", "magic_byte_polyglot", nil},
		{"server rename survival", "rename", "server_rename_survival", nil},
		{"zip slip", "zip", "zip_slip", nil},
		{"tar path traversal", "tar", "zip_slip", func(a fileUploadAttempt) bool { return a.filename == "recon.tar.gz" }},
		{"web-root config", "config", "webroot_config_overwrite", func(a fileUploadAttempt) bool { return a.filename == ".htaccess" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, db, targetID := newFileUploadTestScanner(t)
			lab := newUploadLab(t, tc.mode, nil)
			a := chooseAttempt(t, fileUploadAttempts(oobCapability{}, false, db, targetID, multipartPoint(lab.server.URL+"/vuln/"+tc.mode)), tc.subtype, tc.match)
			if got := runLabAttempt(t, s, db, targetID, multipartPoint(lab.server.URL+"/vuln/"+tc.mode), a); got != 1 {
				t.Fatalf("vulnerable fixture findings=%d, want 1", got)
			}
			if got := runLabAttempt(t, s, db, targetID, multipartPoint(lab.server.URL+"/safe/"+tc.mode), a); got != 0 {
				t.Fatalf("patched fixture findings=%d, want 0", got)
			}
		})
	}
}

func TestFileUploadSVGRequiresBrowserProof(t *testing.T) {
	s, db, targetID := newFileUploadTestScanner(t)
	lab := newUploadLab(t, "svg", nil)
	s.confirmStoredXSS = func(ctx context.Context, rawURL string, _ map[string]string, marker string) bool {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		resp, err := fileUploadClient.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return strings.Contains(string(body), "document.title='"+marker+"'")
	}
	a := chooseAttempt(t, fileUploadAttempts(oobCapability{}, false, db, targetID, multipartPoint(lab.server.URL+"/vuln/svg")), "svg_stored_xss", nil)
	if got := runLabAttempt(t, s, db, targetID, multipartPoint(lab.server.URL+"/vuln/svg"), a); got != 1 {
		t.Fatalf("browser-proven SVG findings=%d, want 1", got)
	}
	if got := runLabAttempt(t, s, db, targetID, multipartPoint(lab.server.URL+"/safe/svg"), a); got != 0 {
		t.Fatalf("patched SVG findings=%d, want 0", got)
	}
}

func TestFileUploadImageAndOOXMLOOBRequireAttributedCallback(t *testing.T) {
	for _, tc := range []struct{ mode, subtype string }{{"oob", "image_processing_ssrf"}, {"ooxml", "ooxml_xxe"}} {
		t.Run(tc.mode, func(t *testing.T) {
			s, db, targetID := newFileUploadTestScanner(t)
			callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := path.Base(r.URL.Path)
				_, _ = db.Exec(`UPDATE oob_probes SET hit_count=hit_count+1,evidence='local attributed callback' WHERE token=?`, token)
				fmt.Fprint(w, "ok")
			}))
			defer callback.Close()
			s.cfg.BlindXSSCallbackURL = callback.URL
			oob, ok := newOOBCapability(s.cfg)
			if !ok {
				t.Fatal("local OOB capability unavailable")
			}
			lab := newUploadLab(t, tc.mode, func(rawURL string) {
				resp, _ := http.Get(rawURL)
				if resp != nil {
					resp.Body.Close()
				}
			}) // #nosec G107 -- httptest-only URL
			ip := multipartPoint(lab.server.URL + "/vuln/" + tc.mode)
			a := chooseAttempt(t, fileUploadAttempts(oob, true, db, targetID, ip), tc.subtype, nil)
			if got := runLabAttempt(t, s, db, targetID, ip, a); got != 1 {
				t.Fatalf("callback-proven finding=%d, want 1", got)
			}
			patched := multipartPoint(lab.server.URL + "/safe/" + tc.mode)
			a2 := chooseAttempt(t, fileUploadAttempts(oob, true, db, targetID, patched), tc.subtype, nil)
			if got := runLabAttempt(t, s, db, targetID, patched, a2); got != 0 {
				t.Fatalf("patched callback finding=%d, want 0", got)
			}
		})
	}
}

func TestFileUploadJSONDiscoveryAndBenignImageFalsePositiveRegression(t *testing.T) {
	if !eligibleFileUploadPoint(insertionPoint{Param: "avatar", Method: "POST", ContentType: "application/json"}) {
		t.Fatal("JSON avatar must be eligible")
	}
	if eligibleFileUploadPoint(insertionPoint{Param: "display_name", Method: "POST", ContentType: "application/json"}) {
		t.Fatal("unrelated JSON field must not be eligible")
	}
	if !eligibleFileUploadPoint(insertionPoint{Param: "content", Method: "POST", ContentType: "application/json", Siblings: map[string]string{"file_name": "old.jpg"}}) {
		t.Fatal("flat base64 content plus filename metadata must be eligible")
	}
	s, db, targetID := newFileUploadTestScanner(t)
	lab := newUploadLab(t, "none", nil)
	a := fileUploadAttempt{name: "benign JPEG", subtype: "content_type_mismatch", filename: "portrait.jpg", contentType: "image/jpeg", body: []byte("\xff\xd8\xffsafe-local-image"), marker: uuid.NewString(), proof: proofExecution}
	if got := runLabAttempt(t, s, db, targetID, multipartPoint(lab.server.URL+"/safe/image"), a); got != 0 {
		t.Fatalf("inert JPEG produced %d finding(s)", got)
	}
}

func TestFileUploadJSONTransportPreservesFlatDiscoveredSchema(t *testing.T) {
	withLoopbackAllowed(t)
	var saw bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var root map[string]any
		_ = json.NewDecoder(r.Body).Decode(&root)
		decoded, err := base64.StdEncoding.DecodeString(fmt.Sprint(root["content"]))
		saw = err == nil && string(decoded) == "local-proof" && root["file_name"] == "recon.phtml" && root["mime_type"] == "application/octet-stream" && root["tenant"] == "local"
		if !saw {
			http.Error(w, "bad flat upload shape", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"file_name":"stored-recon.phtml"}`)
	}))
	defer server.Close()
	s := &FileUploadScanner{}
	ip := insertionPoint{URL: server.URL + "/upload", Param: "content", Value: "Zm9v", Method: "POST", ContentType: "application/json", Location: "json", Siblings: map[string]string{
		"file_name": "old.jpg", "mime_type": "image/jpeg", "tenant": "local",
	}}
	result, err := s.upload(context.Background(), ip, nil, fileUploadAttempt{filename: "recon.phtml", contentType: "application/octet-stream", body: []byte("local-proof")})
	if err != nil || result.status != http.StatusOK || !saw {
		t.Fatalf("flat JSON upload status=%d saw=%v err=%v", result.status, saw, err)
	}
	foundStoredName := false
	for _, candidate := range result.urls {
		if strings.HasSuffix(candidate, "/uploads/stored-recon.phtml") {
			foundStoredName = true
		}
	}
	if !foundStoredName {
		t.Fatalf("filename-only response was not converted into retrieval candidates: %v", result.urls)
	}
}

func TestFileUploadJSONPayloadPreservesNestedAndDiscoveredObjectSchemas(t *testing.T) {
	a := fileUploadAttempt{filename: "proof.svg", contentType: "image/svg+xml", body: []byte("svg-proof")}
	nested := buildJSONUploadPayload(insertionPoint{
		Param: "upload.data", Value: "data:image/png;base64,b2xk", Method: "POST", ContentType: "application/json",
		Siblings: map[string]string{"upload.file_name": "old.png", "upload.mime_type": "image/png", "tenant.id": "7"},
	}, a)
	upload, ok := nested["upload"].(map[string]any)
	if !ok || upload["file_name"] != "proof.svg" || upload["mime_type"] != "image/svg+xml" || !strings.HasPrefix(fmt.Sprint(upload["data"]), "data:image/svg+xml;base64,") {
		t.Fatalf("nested flat schema was not preserved: %#v", nested)
	}
	tenant, ok := nested["tenant"].(map[string]any)
	if !ok || tenant["id"] != "7" {
		t.Fatalf("nested required siblings were lost: %#v", nested)
	}

	object := buildJSONUploadPayload(insertionPoint{
		Param: "file", Value: `{"name":"old.png","type":"image/png","content":"b2xk","metadata":{"public":false}}`, Method: "POST", ContentType: "application/json",
	}, a)
	file, ok := object["file"].(map[string]any)
	if !ok || file["name"] != "proof.svg" || file["type"] != "image/svg+xml" || file["content"] != base64.StdEncoding.EncodeToString(a.body) {
		t.Fatalf("discovered object schema was not reused: %#v", object)
	}
	if _, ok := file["metadata"].(map[string]any); !ok {
		t.Fatalf("unrelated discovered object metadata was dropped: %#v", file)
	}
}

func TestZipSlipDoesNotPromoteMarkerInsideUploadDirectory(t *testing.T) {
	s, _, _ := newFileUploadTestScanner(t)
	marker := "rcnzipinside"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/uploads/"+marker+".txt" {
			fmt.Fprint(w, marker)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	ip := multipartPoint(server.URL + "/uploads/process")
	a := fileUploadAttempt{filename: "recon.zip", marker: marker, proof: proofZipSlip}
	proofURL, evidence := s.verifyZipSlip(context.Background(), ip, nil, a, []string{
		server.URL + "/uploads/recon.zip",
		server.URL + "/uploads/" + marker + ".txt",
	})
	if proofURL != "" || evidence != "" {
		t.Fatalf("safe in-directory extraction became ZIP-slip proof: %q %q", proofURL, evidence)
	}
}

func TestFileUploadRunConsumesDiscoveredMultipartInsertionPoint(t *testing.T) {
	s, db, targetID := newFileUploadTestScanner(t)
	lab := newUploadLab(t, "blacklist", nil)
	seedV3Parameter(t, db, targetID, lab.server.URL+"/vuln/blacklist", "file", "", "POST", "multipart/form-data", "body")
	seedV3Parameter(t, db, targetID, lab.server.URL+"/vuln/blacklist", "csrf", "local-test", "POST", "multipart/form-data", "body")
	if err := s.Run(context.Background(), targetID, func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}
	if got := v3FindingCount(t, db, targetID, "file_upload", "/vuln/blacklist"); got != 1 {
		t.Fatalf("end-to-end file-upload findings=%d, want 1", got)
	}
}

func TestFileUploadJSONTransportUsesStructuredFileObject(t *testing.T) {
	withLoopbackAllowed(t)
	var sawSibling bool
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var root map[string]any
		_ = json.NewDecoder(r.Body).Decode(&root)
		sawSibling = root["tenant"] == "local"
		avatar, ok := root["avatar"].(map[string]any)
		if !ok || avatar["filename"] != "recon.phtml" || avatar["content_type"] != "application/octet-stream" {
			http.Error(w, "bad JSON upload shape", http.StatusBadRequest)
			return
		}
		if _, err := base64.StdEncoding.DecodeString(fmt.Sprint(avatar["data"])); err != nil {
			http.Error(w, "bad base64", http.StatusBadRequest)
			return
		}
		writeUploadJSON(w, server.URL+"/uploads/recon.phtml")
	}))
	defer server.Close()
	s := &FileUploadScanner{}
	ip := insertionPoint{URL: server.URL + "/upload", Param: "avatar", Method: "POST", ContentType: "application/json", Location: "json", Siblings: map[string]string{"tenant": "local"}}
	result, err := s.upload(context.Background(), ip, nil, fileUploadAttempt{filename: "recon.phtml", contentType: "application/octet-stream", body: []byte("local")})
	if err != nil || result.status != http.StatusOK || !sawSibling {
		t.Fatalf("JSON upload status=%d sibling=%v err=%v", result.status, sawSibling, err)
	}
}

// Compile-time assertion that the production request remains a real file part,
// not a normal text field (the bug that originally made multipart candidates inert).
func TestFileUploadMultipartCarriesFilenameAndMIME(t *testing.T) {
	var seen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			t.Error(err)
			return
		}
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Error(err)
				break
			}
			if p.FormName() == "file" && p.FileName() == "recon.phtml" && p.Header.Get("Content-Type") == "application/octet-stream" {
				seen = true
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"url":"/uploads/recon.phtml"}`)
	}))
	defer server.Close()
	withLoopbackAllowed(t)
	s := &FileUploadScanner{}
	_, _ = s.upload(context.Background(), multipartPoint(server.URL+"/upload"), nil, fileUploadAttempt{filename: "recon.phtml", contentType: "application/octet-stream", body: []byte("proof")})
	if !seen {
		t.Fatal("multipart file metadata was not preserved")
	}
}

func TestFileUploadAttemptMatrixIsComplete(t *testing.T) {
	db, targetID := newV3ScannerDB(t)
	ip := multipartPoint("https://example.local/upload")
	attempts := fileUploadAttempts(oobCapability{callbackBase: "https://example.local"}, true, db, targetID, ip)
	if len(attempts) < 42 {
		t.Fatalf("upload attempt matrix regressed to %d entries, want at least 42", len(attempts))
	}
	files := map[string]bool{}
	languages := map[string]bool{}
	for _, a := range attempts {
		files[a.filename] = true
		if a.proof == proofExecution && bytes.Contains(a.body, []byte(a.marker)) {
			t.Errorf("execution payload %q embeds its complete proof marker and could be mistaken for inert retrieval", a.filename)
		}
		if a.subtype == "content_type_mismatch" {
			languages[path.Ext(a.filename)] = a.contentType == "image/jpeg"
		}
	}
	for _, filename := range []string{
		"recon.phtml", "recon.pht", "recon.phar", "recon.php5", "recon.php7", "recon.inc", "recon.PhP", "recon.jspx", "recon.asp", "recon.asa", "recon.cer", "recon.cfm", "recon.cfml",
		"recon.php.jpg", "recon.jpg.php", "recon.php%00.jpg", "recon.php ", "recon.php.", "recon.php;.jpg", "recon.p.phphp", "recon.php::$DATA.jpg", "recon.php...jpg",
		"recon.php", "recon.jsp", "recon.aspx", "recon.php.gif", "recon-rename.php",
		"recon.svg", "recon-oob.svg", "recon-oob.mvg", "recon.zip", "recon.tar.gz", "recon.docx", "recon.xlsx", "recon.pptx",
		".htaccess", "web.config",
	} {
		if !files[filename] {
			t.Errorf("required upload attempt %q missing", filename)
		}
	}
	for _, ext := range []string{".php", ".jsp", ".aspx"} {
		if !languages[ext] {
			t.Errorf("%s content mismatch is not sent as image/jpeg", ext)
		}
	}
}
