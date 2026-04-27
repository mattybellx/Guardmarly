from flask import Flask, abort, g
from .auth import admin_required, login_required

app = Flask(__name__)


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    return []


@app.route('/invoice/<invoice_id>')
@login_required
def get_invoice(invoice_id):
    row = db.execute(
        'SELECT * FROM invoices WHERE id = ? AND owner_id = ?',
        (invoice_id, g.user_id),
    ).fetchone()
    if row is None:
        abort(404)
    return row
