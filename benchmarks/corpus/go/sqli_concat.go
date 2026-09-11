package main

import (
	"database/sql"
	"net/http"
)

func user(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	row := db.QueryRow("SELECT * FROM users WHERE name = '" + name + "'")
	_ = row
	_ = sql.ErrNoRows
}
