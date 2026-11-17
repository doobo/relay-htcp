// Package ui embeds the single-page admin web interface.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html app.js style.css favicon.svg vendor/tweetnacl.js
var assets embed.FS

// Handler serves the embedded admin UI at /.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, ".")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	mux := http.NewServeMux()
	// The assets are embedded in the binary and change on every upgrade, but
	// they have no ETag/Last-Modified metadata. Force clients to revalidate so
	// an old app.js cannot hide newly added pages (for example the proxy tab).
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		fileServer.ServeHTTP(w, r)
	}))
	return mux
}
