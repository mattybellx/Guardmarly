package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, _ := os.ReadFile(filepath.Join("/srv/files", name))
	w.Write(data)
}
