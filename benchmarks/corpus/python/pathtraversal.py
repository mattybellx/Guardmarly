import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/download")
def download():
    name = request.args.get("file")
    with open(os.path.join("/srv/files", name)) as fh:
        return fh.read()
