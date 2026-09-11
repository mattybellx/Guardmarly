package main

import "net/http"

func user(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	row := db.QueryRow("SELECT * FROM users WHERE name = $1", name)
	_ = row
}
