from flask import Flask, request

app = Flask(__name__)


@app.route("/order")
def order():
    oid = request.args.get("id")
    cursor = get_cursor()
    cursor.execute(f"SELECT * FROM orders WHERE id = {oid}")
    return "ok"
