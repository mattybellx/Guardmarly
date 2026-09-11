import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], check=False)
    return "pong"
