// Package disguise adds browser-like camouflage to relay-htcp traffic.
package disguise

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// DefaultUserAgent is a common desktop Chrome user agent.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// ImpersonatedServerHeader is what decoy and tunnel responses report
// instead of the real Go server.
const ImpersonatedServerHeader = "nginx/1.24.0"

// Apply sets browser-style request headers on req. Existing headers such as
// Authorization or X-Tunnel-* are left untouched.
func Apply(req *http.Request, userAgent string) {
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

var decoyViews atomic.Uint64

// Decoy serves a small static page so unauthenticated scanners see an
// ordinary under-construction website.
func Decoy(w http.ResponseWriter, r *http.Request) {
	decoyViews.Add(1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Server", ImpersonatedServerHeader)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, page, time.Now().UTC().Format("2006-01-02"))
}

// Views reports how many decoy pages were served (diagnostics).
func Views() uint64 { return decoyViews.Load() }

const page = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f7f8fa}
.card{text-align:center;padding:48px 64px;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);color:#333}
h1{font-size:22px;margin:0 0 8px}p{color:#888;margin:0}
</style>
</head>
<body>
<div class="card">
<h1>This site is under construction</h1>
<p>Coming back soon — %s</p>
</div>
</body>
</html>
`
