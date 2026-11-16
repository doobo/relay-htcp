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
	mux.Handle("/", fileServer)
	return mux
}
