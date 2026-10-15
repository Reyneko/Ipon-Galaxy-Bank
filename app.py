import os
import random
import secrets
import uuid
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from dotenv import load_dotenv
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

BANK_NAME = "Ipon Galaxy Bank"
BANK_TAGLINE = "Saving pesos across the universe"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-me")

db_url = os.getenv("DATABASE_URL", "sqlite:///bank.db")
if db_url.startswith("postgres://"):  # Render gives postgres://, SQLAlchemy wants postgresql://
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)  # idle timeout
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(os.getenv("RENDER"))

db = SQLAlchemy(app)

MAX_PIN_ATTEMPTS = 3
DAILY_WITHDRAW_LIMIT = Decimal("50000.00")
MAX_SINGLE_TXN = Decimal("100000.00")


# ----------------------------------------------------------------- models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(10), nullable=False, default="customer")  # admin | customer
    username = db.Column(db.String(40), unique=True)          # admin login
    account_number = db.Column(db.String(12), unique=True)    # customer login
    full_name = db.Column(db.String(80), nullable=False)
    secret_hash = db.Column(db.String(255), nullable=False)   # PIN (customer) / password (admin)
    balance = db.Column(db.Numeric(14, 2), nullable=False, default=0)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked = db.Column(db.Boolean, nullable=False, default=False)
    must_change_pin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    kind = db.Column(db.String(12), nullable=False)  # deposit | withdrawal | opening
    amount = db.Column(db.Numeric(14, 2), nullable=False)
    balance_after = db.Column(db.Numeric(14, 2), nullable=False)
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    event = db.Column(db.String(40), nullable=False)
    detail = db.Column(db.String(255))
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship("User")


# ---------------------------------------------------------------- helpers
def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() if fwd else request.remote_addr) or "unknown"


def log(event, detail="", user_id=None):
    db.session.add(AuditLog(
        user_id=user_id, event=event, detail=detail[:255],
        ip_address=client_ip(), user_agent=(request.user_agent.string or "")[:200]))


def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None


def to_money(value):
    try:
        d = Decimal(str(value)).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return None
    return d


def peso(value):
    return "₱{:,.2f}".format(value)


def pin_ok(pin):
    return isinstance(pin, str) and pin.isdigit() and len(pin) == 4


def login_required(role):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = current_user()
            if not user or user.role != role:
                if request.path.startswith("/api/"):
                    return jsonify(ok=False, error="Session expired. Please log in again."), 401
                flash("Please log in to continue.", "info")
                return redirect(url_for("login"))
            session.permanent = True  # refresh idle timer
            if user.locked and role == "customer":
                session.clear()
                return redirect(url_for("login"))
            return fn(user, *a, **kw)
        return wrapper
    return deco


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not sent or sent != session.get("csrf"):
            if request.path.startswith("/api/"):
                return jsonify(ok=False, error="Security token expired. Refresh the page."), 400
            abort(400, "Invalid security token. Go back and refresh the page.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


app.jinja_env.globals.update(csrf_token=csrf_token, bank_name=BANK_NAME,
                             bank_tagline=BANK_TAGLINE, peso=peso)


def new_account_number():
    while True:
        num = "".join(random.choices("0123456789", k=10))
        if not User.query.filter_by(account_number=num).first():
            return num


def new_reference():
    return "IGB-" + uuid.uuid4().hex[:10].upper()


def register_failed_pin(user):
    """Count a wrong PIN; lock the account on the 3rd. Returns attempts left."""
    user.failed_attempts += 1
    left = MAX_PIN_ATTEMPTS - user.failed_attempts
    if left <= 0:
        user.locked = True
        log("ACCOUNT_LOCKED", "Too many wrong PIN attempts", user.id)
    else:
        log("PIN_FAILED", f"{left} attempt(s) left", user.id)
    db.session.commit()
    return max(left, 0)


# ----------------------------------------------------------------- routes
@app.route("/")
def index():
    user = current_user()
    if user:
        return redirect(url_for("admin_home" if user.role == "admin" else "dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    mode = request.form.get("mode", "customer")
    identifier = request.form.get("identifier", "").strip()
    secret = request.form.get("secret", "")
    generic_error = "Invalid credentials."

    if mode == "admin":
        user = User.query.filter_by(role="admin", username=identifier).first()
        if user and check_password_hash(user.secret_hash, secret):
            session.clear()
            session["uid"] = user.id
            session.permanent = True
            user.last_login = datetime.utcnow()
            log("ADMIN_LOGIN", "", user.id)
            db.session.commit()
            return redirect(url_for("admin_home"))
        log("ADMIN_LOGIN_FAILED", f"username={identifier[:30]}")
        db.session.commit()
        flash(generic_error, "error")
        return redirect(url_for("login", mode="admin"))

    user = User.query.filter_by(role="customer", account_number=identifier).first()
    if user and user.locked:
        flash("This account is locked. Please contact the bank admin.", "error")
        return redirect(url_for("login"))
    if user and check_password_hash(user.secret_hash, secret):
        user.failed_attempts = 0
        user.last_login = datetime.utcnow()
        session.clear()
        session["uid"] = user.id
        session.permanent = True
        log("LOGIN", "", user.id)
        db.session.commit()
        return redirect(url_for("dashboard"))
    if user:
        left = register_failed_pin(user)
        flash("Account locked after too many wrong PINs." if left == 0
              else f"Wrong PIN. {left} attempt(s) left.", "error")
    else:
        log("LOGIN_FAILED", f"unknown account {identifier[:12]}")
        db.session.commit()
        flash(generic_error, "error")
    return redirect(url_for("login"))


@app.route("/logout", methods=["POST"])
def logout():
    user = current_user()
    if user:
        log("LOGOUT", "", user.id)
        db.session.commit()
    session.clear()
    flash("You have been logged out safely.", "info")
    return redirect(url_for("login"))


# ------------------------------------------------------------------ admin
@app.route("/admin")
@login_required("admin")
def admin_home(admin):
    customers = User.query.filter_by(role="customer").order_by(User.created_at.desc()).all()
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(25).all()
    total = sum((c.balance for c in customers), Decimal("0"))
    new_cred = session.pop("new_customer", None)
    return render_template("admin.html", admin=admin, customers=customers,
                           logs=logs, total=total, new_cred=new_cred)


@app.route("/admin/customers", methods=["POST"])
@login_required("admin")
def admin_create_customer(admin):
    name = request.form.get("full_name", "").strip()
    opening = to_money(request.form.get("opening_balance") or "0")
    if not name or len(name) > 80:
        flash("Please enter the customer's full name.", "error")
        return redirect(url_for("admin_home"))
    if opening is None or opening < 0 or opening > MAX_SINGLE_TXN:
        flash("Opening balance must be between ₱0 and ₱100,000.", "error")
        return redirect(url_for("admin_home"))

    default_pin = f"{secrets.randbelow(10000):04d}"
    cust = User(role="customer", full_name=name, account_number=new_account_number(),
                secret_hash=generate_password_hash(default_pin),
                balance=opening, must_change_pin=True)
    db.session.add(cust)
    db.session.flush()
    if opening > 0:
        db.session.add(Transaction(reference=new_reference(), user_id=cust.id, kind="opening",
                                   amount=opening, balance_after=opening, ip_address=client_ip()))
    log("CUSTOMER_CREATED", f"{name} / {cust.account_number}", admin.id)
    db.session.commit()
    # show the default PIN exactly once
    session["new_customer"] = {"name": name, "account": cust.account_number, "pin": default_pin}
    return redirect(url_for("admin_home"))


@app.route("/admin/customers/<int:cid>/reset", methods=["POST"])
@login_required("admin")
def admin_reset(admin, cid):
    cust = db.session.get(User, cid)
    if not cust or cust.role != "customer":
        abort(404)
    default_pin = f"{secrets.randbelow(10000):04d}"
    cust.secret_hash = generate_password_hash(default_pin)
    cust.must_change_pin = True
    cust.failed_attempts = 0
    cust.locked = False
    log("PIN_RESET_BY_ADMIN", cust.account_number, admin.id)
    db.session.commit()
    session["new_customer"] = {"name": cust.full_name, "account": cust.account_number,
                               "pin": default_pin}
    return redirect(url_for("admin_home"))


@app.route("/admin/customers/<int:cid>/toggle-lock", methods=["POST"])
@login_required("admin")
def admin_toggle_lock(admin, cid):
    cust = db.session.get(User, cid)
    if not cust or cust.role != "customer":
        abort(404)
    cust.locked = not cust.locked
    cust.failed_attempts = 0
    log("ACCOUNT_LOCKED_BY_ADMIN" if cust.locked else "ACCOUNT_UNLOCKED_BY_ADMIN",
        cust.account_number, admin.id)
    db.session.commit()
    flash(f"{cust.full_name}'s account is now {'locked' if cust.locked else 'unlocked'}.", "info")
    return redirect(url_for("admin_home"))


# --------------------------------------------------------------- customer
@app.route("/dashboard")
@login_required("customer")
def dashboard(user):
    txns = (Transaction.query.filter_by(user_id=user.id)
            .order_by(Transaction.created_at.desc(), Transaction.id.desc()).limit(15).all())
    events = (AuditLog.query.filter_by(user_id=user.id)
              .order_by(AuditLog.created_at.desc()).limit(5).all())
    return render_template("dashboard.html", user=user, txns=txns, events=events)


def txn_json(t):
    return {"reference": t.reference, "kind": t.kind, "amount": f"{t.amount:,.2f}",
            "balance_after": f"{t.balance_after:,.2f}",
            "time": t.created_at.strftime("%b %d, %Y %I:%M %p") + " UTC"}


@app.route("/api/transaction", methods=["POST"])
@login_required("customer")
def api_transaction(user):
    data = request.get_json(silent=True) or {}
    kind = data.get("kind")
    amount = to_money(data.get("amount"))
    pin = str(data.get("pin", ""))

    if user.must_change_pin:
        return jsonify(ok=False, error="Please change your default PIN first."), 403
    if kind not in ("deposit", "withdrawal"):
        return jsonify(ok=False, error="Invalid transaction type."), 400
    if amount is None or amount <= 0 or amount > MAX_SINGLE_TXN:
        return jsonify(ok=False, error="Enter an amount between ₱0.01 and ₱100,000."), 400

    # Security check #1: PIN re-entry for EVERY transaction
    if not check_password_hash(user.secret_hash, pin):
        left = register_failed_pin(user)
        if left == 0:
            session.clear()
            return jsonify(ok=False, locked=True,
                           error="Account locked after 3 wrong PINs. Contact the admin."), 403
        return jsonify(ok=False, error=f"Wrong PIN. {left} attempt(s) left."), 403
    user.failed_attempts = 0

    if kind == "withdrawal":
        if amount > user.balance:
            return jsonify(ok=False, error="Insufficient balance."), 400
        start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        used = sum((t.amount for t in Transaction.query.filter(
            Transaction.user_id == user.id, Transaction.kind == "withdrawal",
            Transaction.created_at >= start)), Decimal("0"))
        if used + amount > DAILY_WITHDRAW_LIMIT:
            return jsonify(ok=False, error=f"Daily withdrawal limit is {peso(DAILY_WITHDRAW_LIMIT)}. "
                                           f"You have {peso(DAILY_WITHDRAW_LIMIT - used)} left today."), 400
        user.balance -= amount
    else:
        user.balance += amount

    txn = Transaction(reference=new_reference(), user_id=user.id, kind=kind, amount=amount,
                      balance_after=user.balance, ip_address=client_ip())
    db.session.add(txn)
    log(kind.upper(), f"{peso(amount)} ref {txn.reference}", user.id)
    db.session.commit()

    # Security check #2 (after every transaction): rotate the CSRF token, and the
    # client re-locks the form + shows a receipt with a "Not me? Lock account" panic button.
    session["csrf"] = secrets.token_hex(16)
    return jsonify(ok=True, balance=f"{user.balance:,.2f}", txn=txn_json(txn),
                   csrf=session["csrf"], ip=client_ip(),
                   message="Transaction successful. Your form has been re-locked for safety.")


@app.route("/api/change-pin", methods=["POST"])
@login_required("customer")
def api_change_pin(user):
    data = request.get_json(silent=True) or {}
    old, new, confirm = (str(data.get(k, "")) for k in ("old_pin", "new_pin", "confirm_pin"))
    if not check_password_hash(user.secret_hash, old):
        left = register_failed_pin(user)
        if left == 0:
            session.clear()
            return jsonify(ok=False, locked=True, error="Account locked. Contact the admin."), 403
        return jsonify(ok=False, error=f"Current PIN is wrong. {left} attempt(s) left."), 403
    if not pin_ok(new):
        return jsonify(ok=False, error="New PIN must be exactly 4 digits."), 400
    if new != confirm:
        return jsonify(ok=False, error="New PIN and confirmation don't match."), 400
    if new == old:
        return jsonify(ok=False, error="New PIN must be different from the current one."), 400
    if len(set(new)) == 1 or new in ("1234", "4321", "0123"):
        return jsonify(ok=False, error="That PIN is too easy to guess. Pick another."), 400
    user.secret_hash = generate_password_hash(new)
    user.must_change_pin = False
    user.failed_attempts = 0
    log("PIN_CHANGED", "", user.id)
    db.session.commit()
    return jsonify(ok=True, message="PIN changed successfully.")


@app.route("/api/panic-lock", methods=["POST"])
@login_required("customer")
def api_panic_lock(user):
    user.locked = True
    log("ACCOUNT_LOCKED", "Customer pressed 'Not me' after a transaction", user.id)
    db.session.commit()
    session.clear()
    return jsonify(ok=True, message="Account locked. Please contact the bank admin.")


# -------------------------------------------------------------- bootstrap
def init_db():
    db.create_all()
    admin_user = os.getenv("ADMIN_USERNAME", "admin")
    admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    if not User.query.filter_by(role="admin").first():
        db.session.add(User(role="admin", username=admin_user, full_name="Bank Administrator",
                            secret_hash=generate_password_hash(admin_pass)))
        db.session.commit()


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
