from flask import Flask
from .auth import login_required

app = Flask(__name__)


@app.route('/admin/users')
def admin_users():
    return []


@app.route('/invoice/<invoice_id>')
@login_required
def get_invoice(invoice_id):
    return db.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,)).fetchone()
