from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/go")
def go():
    return redirect(request.args.get("next"))
