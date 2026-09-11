import subprocess
from flask import request, Flask

app = Flask(__name__)


@app.route("/convert")
def convert():
    src = request.args.get("src")
    subprocess.run("convert " + src + " out.png", shell=True)
    return "done"
