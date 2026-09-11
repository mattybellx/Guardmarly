package main

import (
	"net/http"
	"os/exec"
)

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	_ = cmd.Run()
}
