import re
import time
from functools import wraps

from flask import Blueprint, g, jsonify, request, session
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from .models import User, db

bp = Blueprint("auth", __name__, url_prefix="/api")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
DUMMY_HASH = generate_password_hash("netrec-timing-equaliser")
FAILS = {}  # (ip, username) -> [timestamps]; in-memory, fine for 1 worker


def err(msg, code=400):
    return jsonify(error=msg), code


def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        uid = session.get("uid")
        user = db.session.get(User, uid) if uid else None
        if not user:
            return err("Not authenticated", 401)
        g.uid, g.username = user.id, user.username
        return f(*a, **k)
    return wrapper


def _start_session(user):
    session.clear()
    session["uid"] = user.id
    return jsonify(username=user.username)


@bp.post("/register")
def register():
    d = request.get_json(silent=True) or {}
    name, pw = str(d.get("username", "")).strip().lower(), str(d.get("password", ""))
    if not USER_RE.match(name):
        return err("Username: 3-32 characters, letters, digits, . _ -")
    if not 8 <= len(pw) <= 128:
        return err("Password must be 8-128 characters")
    user = User(username=name, password_hash=generate_password_hash(pw))  # scrypt + per-user salt
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return err("Username already taken", 409)
    return _start_session(user)


@bp.post("/login")
def login():
    d = request.get_json(silent=True) or {}
    name, pw = str(d.get("username", "")).strip().lower(), str(d.get("password", ""))
    key, now = (request.remote_addr, name), time.time()
    FAILS[key] = [t for t in FAILS.get(key, []) if now - t < 300]
    if len(FAILS[key]) >= 5:
        return err("Too many attempts. Try again in a few minutes", 429)
    user = User.query.filter_by(username=name).first()
    ok = check_password_hash(user.password_hash if user else DUMMY_HASH, pw)
    if not (user and ok):
        FAILS[key].append(now)
        return err("Invalid username or password", 401)
    FAILS.pop(key, None)
    return _start_session(user)


@bp.post("/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@bp.get("/me")
@login_required
def me():
    return jsonify(username=g.username)
