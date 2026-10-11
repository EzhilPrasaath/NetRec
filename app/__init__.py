import time

from flask import Flask, jsonify, request
from sqlalchemy.exc import OperationalError

from .models import Scan, db


def create_app():
    app = Flask(__name__, static_folder="static", static_url_path="")
    app.config.from_object("app.config.Config")
    db.init_app(app)

    with app.app_context():
        for _ in range(30):  # wait for Postgres, then create tables automatically
            try:
                db.create_all()
                break
            except OperationalError:
                time.sleep(2)
        else:
            raise RuntimeError("Database not reachable")
        Scan.query.filter(Scan.status.in_(("queued", "running"))).update(
            {"status": "failed", "error": "Interrupted by server restart"}, synchronize_session=False)
        db.session.commit()

    from . import auth, scans
    app.register_blueprint(auth.bp)
    app.register_blueprint(scans.bp)

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.before_request
    def csrf_guard():  # cross-site forms cannot send application/json without a CORS preflight
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and not request.is_json:
            return jsonify(error="JSON body required"), 415

    @app.after_request
    def headers(r):
        r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; object-src 'none'"
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Referrer-Policy"] = "no-referrer"
        r.headers["Cache-Control"] = "no-store" if request.path.startswith("/api") else r.headers.get("Cache-Control", "no-cache")
        return r

    return app
