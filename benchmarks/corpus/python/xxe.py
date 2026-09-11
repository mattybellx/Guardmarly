from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse():
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(request.get_data(), parser)
    return etree.tostring(tree)
