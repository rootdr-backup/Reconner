package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/recon-platform/internal/models"
)

type LogFunc func(level, module, message string)

var probeHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

func probeURL(url string) *models.HTTPService {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")

	resp, err := probeHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}

	title := extractTitle(string(body))
	server := resp.Header.Get("Server")
	contentType := resp.Header.Get("Content-Type")

	return &models.HTTPService{
		URL:           url,
		StatusCode:    resp.StatusCode,
		Title:         title,
		Server:        server,
		ContentType:   contentType,
		ContentLength: len(body),
	}
}

func extractTitle(body string) string {
	if !utf8.ValidString(body) {
		return ""
	}

	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}

	title := strings.TrimSpace(body[start : start+end])
	if len(title) > 255 {
		title = title[:255]
	}
	return title
}

// titleFirst upper-cases the first byte of an ASCII word (e.g. "mongodb" →
// "Mongodb"). Used for display labels of service names; replaces the deprecated
// strings.Title without pulling in golang.org/x/text for a one-letter change.
func titleFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 'a' - 'A'
	}
	return string(b)
}
