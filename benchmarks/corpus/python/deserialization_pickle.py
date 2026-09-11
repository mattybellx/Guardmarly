import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def load():
    blob = request.get_data()
    obj = pickle.loads(blob)
    return str(obj)
