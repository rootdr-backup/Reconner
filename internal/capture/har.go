package capture

import (
        "bytes"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io"
        "net/url"
        "strings"
        "time"
)

// HAR 1.2 structures (http://www.softwareishard.com/blog/har-12-spec/).
// Only the fields the canonical Exchange needs are modeled; the spec allows
// exporters to add extension fields, so unknown fields are ignored (unlike
// the Reconner JSON envelope, which is ours and strict).
type harFile struct {
        Log harLog `json:"log"`
}

type harLog struct {
        Version string     `json:"version"`
        Creator *harName   `json:"creator,omitempty"`
        Entries []harEntry `json:"entries"`
}

type harName struct {
        Name    string `json:"name"`
        Version string `json:"version"`
}

type harEntry struct {
        StartedDateTime string      `json:"startedDateTime"`
        Time            float64     `json:"time"`
        Request         harRequest  `json:"request"`
        Response        harResponse `json:"response"`
}

type harRequest struct {
        Method      string     `json:"method"`
        URL         string     `json:"url"`
        HTTPVersion string     `json:"httpVersion"`
        Headers     []harField `json:"headers"`
        Cookies     []harField `json:"cookies"`
        QueryString []harField `json:"queryString"`
        PostData    *harBody   `json:"postData"`
}

type harResponse struct {
        Status      int        `json:"status"`
        HTTPVersion string     `json:"httpVersion"`
        Headers     []harField `json:"headers"`
        Content     harContent `json:"content"`
        RedirectURL string     `json:"redirectURL"`
}

type harField struct {
        Name  string `json:"name"`
        Value string `json:"value"`
}

type harBody struct {
        MimeType string `json:"mimeType"`
        Text     string `json:"text"`
        // Encoding is only produced by response content; request postData is
        // always plain text. Shared here so one decoder serves both shapes.
        Encoding string `json:"encoding,omitempty"`
}

type harContent struct {
        Size     int    `json:"size"`
        MimeType string `json:"mimeType"`
        Text     string `json:"text"`
        Encoding string `json:"encoding"`
}

// ParseHAR parses a HAR 1.2 export (DevTools "Save all as HAR", Charles,
// Fiddler, mitmproxy's hardump). Importing is passive: this function only
// decodes, it never sends requests. Sanitized exports (bodies stripped by the
// exporting tool) import fine; entries simply carry empty bodies.
func ParseHAR(raw []byte) ([]Exchange, error) {
        if len(raw) > MaxImportBytes {
                return nil, ErrImportTooLarge
        }
        dec := json.NewDecoder(bytes.NewReader(raw))
        var file harFile
        if err := dec.Decode(&file); err != nil {
                return nil, fmt.Errorf("invalid HAR JSON: %w", err)
        }
        // A second JSON value (or any non-whitespace suffix) is never part of a
        // HAR file. Reject it instead of silently accepting an ambiguous upload
        // whose validated prefix differs from its full contents.
        var trailing any
        if err := dec.Decode(&trailing); err != io.EOF {
                if err == nil {
                        return nil, fmt.Errorf("invalid HAR JSON: trailing data")
                }
                return nil, fmt.Errorf("invalid HAR JSON: %w", err)
        }
        version := strings.TrimSpace(file.Log.Version)
        if version != "1.1" && version != "1.2" {
                return nil, fmt.Errorf("unsupported HAR version %q (want 1.2)", file.Log.Version)
        }
        if len(file.Log.Entries) == 0 {
                return nil, fmt.Errorf("HAR file contains no entries")
        }
        if len(file.Log.Entries) > MaxItems {
                return nil, fmt.Errorf("capture contains more than %d items", MaxItems)
        }
        out := make([]Exchange, 0, len(file.Log.Entries))
        for i, entry := range file.Log.Entries {
                ex, err := convertHAREntry(entry, i+1)
                if err != nil {
                        return nil, fmt.Errorf("HAR entry %d: %w", i+1, err)
                }
                out = append(out, ex)
        }
        return out, nil
}

func convertHAREntry(entry harEntry, sequence int) (Exchange, error) {
        rawURL := strings.TrimSpace(entry.Request.URL)
        u, err := url.Parse(rawURL)
        if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
                return Exchange{}, fmt.Errorf("invalid HTTP URL")
        }
        method := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
        if method == "" {
                return Exchange{}, fmt.Errorf("no request method")
        }

        reqBody, reqMime, err := harBodyBytes(entry.Request.PostData, "request")
        if err != nil {
                return Exchange{}, err
        }
        respBody, respMime, err := harBodyBytes(&harBody{
                MimeType: entry.Response.Content.MimeType,
                Text:     entry.Response.Content.Text,
                Encoding: entry.Response.Content.Encoding,
        }, "response")
        if err != nil {
                return Exchange{}, err
        }
        if len(entry.Request.Headers) > 256 || len(entry.Response.Headers) > 256 {
                return Exchange{}, fmt.Errorf("too many headers")
        }

        ex := Exchange{
                Source:   "har",
                Sequence: sequence,
                Request: Request{
                        Method:      method,
                        URL:         u.String(),
                        HTTPVersion: strings.TrimSpace(entry.Request.HTTPVersion),
                        Headers:     harHeaders(entry.Request.Headers),
                        Body:        reqBody,
                        MimeType:    reqMime,
                },
                Response: Response{
                        Status:      entry.Response.Status,
                        HTTPVersion: strings.TrimSpace(entry.Response.HTTPVersion),
                        Headers:     harHeaders(entry.Response.Headers),
                        Body:        respBody,
                        MimeType:    respMime,
                        TimeMS:      int64(entry.Time),
                },
        }
        if t, err := time.Parse(time.RFC3339, strings.TrimSpace(entry.StartedDateTime)); err == nil {
                ex.StartedAt = t
        }
        return ex, nil
}

func harBodyBytes(b *harBody, what string) ([]byte, string, error) {
        if b == nil {
                return nil, "", nil
        }
        mime := strings.TrimSpace(b.MimeType)
        if b.Text == "" {
                return nil, mime, nil
        }
        text := b.Text
        if strings.EqualFold(strings.TrimSpace(b.Encoding), "base64") {
                compact := strings.Map(func(r rune) rune {
                        if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
                                return -1
                        }
                        return r
                }, text)
                decoded, err := base64.StdEncoding.DecodeString(compact)
                if err != nil {
                        return nil, "", fmt.Errorf("%s body has invalid base64 content: %w", what, err)
                }
                text = string(decoded)
        }
        if len(text) > MaxMessageBytes {
                return nil, "", fmt.Errorf("%s body exceeds %d bytes", what, MaxMessageBytes)
        }
        return []byte(text), mime, nil
}

func harHeaders(fields []harField) []Header {
        if len(fields) == 0 {
                return nil
        }
        out := make([]Header, 0, len(fields))
        for _, f := range fields {
                name := strings.TrimSpace(f.Name)
                if name == "" {
                        continue
                }
                out = append(out, Header{Name: name, Value: f.Value})
        }
        if len(out) == 0 {
                return nil
        }
        return out
}
