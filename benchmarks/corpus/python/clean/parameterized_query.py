import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cur.fetchall())
