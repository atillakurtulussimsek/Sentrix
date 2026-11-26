package server

import (
	"compress/gzip"
	"io"
	"net/http"
)

// gunzipBody transparently decompresses gzip request bodies from agents.
func gunzipBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(io.LimitReader(r.Body, maxAgentBody))
			if err != nil {
				http.Error(w, "bad gzip body", http.StatusBadRequest)
				return
			}
			defer zr.Close()
			r.Body = io.NopCloser(io.LimitReader(zr, maxAgentBody))
			r.Header.Del("Content-Encoding")
		}
		next.ServeHTTP(w, r)
	})
}
