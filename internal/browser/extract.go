package browser

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
)

// captureFrom pulls the authenticated context out of a live chromedp context:
// ALL cookies (incl. HttpOnly session cookies — the important ones, invisible to
// document.cookie), localStorage, and the user-agent. Only material for the
// target origin's host is kept.
func captureFrom(ctx context.Context, origin string) (CapturedContext, error) {
	host := hostOf(origin)
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out := CapturedContext{Origin: origin, LocalStorage: map[string]string{}}

	var ua string
	var lsJSON []byte
	err := chromedp.Run(cctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			cookies, err := storage.GetCookies().Do(ctx)
			if err != nil {
				return err
			}
			var pairs []string
			for _, c := range cookies {
				cd := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
				if cd == "" || host == cd || strings.HasSuffix(host, "."+cd) {
					pairs = append(pairs, c.Name+"="+c.Value)
				}
			}
			sort.Strings(pairs)
			out.CookieHeader = strings.Join(pairs, "; ")
			return nil
		}),
		chromedp.Evaluate(`navigator.userAgent`, &ua),
		chromedp.Evaluate(`JSON.stringify(Object.assign({}, window.localStorage))`, &lsJSON),
	)
	if err != nil {
		return out, err
	}
	out.UserAgent = ua
	if len(lsJSON) > 0 {
		_ = unmarshalStringMap(lsJSON, out.LocalStorage)
	}
	return out, nil
}
