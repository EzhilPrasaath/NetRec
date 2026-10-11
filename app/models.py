from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    return dt.isoformat() + "Z" if dt else None


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True, nullable=False)
    target = db.Column(db.String(100), nullable=False)       # what the user typed
    nmap_target = db.Column(db.String(100), nullable=False)  # what nmap actually receives
    profile = db.Column(db.String(16), nullable=False)
    ports = db.Column(db.String(200))                        # None = profile default
    timeout_min = db.Column(db.Integer, nullable=False)
    assume_up = db.Column(db.Boolean, default=False)
    authorized = db.Column(db.Boolean, nullable=False)       # audit: user attested permission
    source_ip = db.Column(db.String(64))
    status = db.Column(db.String(16), default="queued", index=True)
    phase = db.Column(db.String(64), default="Queued")
    progress = db.Column(db.Integer, default=0)
    error = db.Column(db.Text)
    result = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=utcnow)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)

    def to_dict(self, full=False):
        d = {
            "id": self.id, "target": self.target, "profile": self.profile,
            "ports": self.ports, "timeout_min": self.timeout_min,
            "status": self.status, "phase": self.phase, "progress": self.progress,
            "error": self.error, "created_at": iso(self.created_at),
            "started_at": iso(self.started_at), "finished_at": iso(self.finished_at),
        }
        if full:
            d["result"] = self.result
        return d


class CVECache(db.Model):
    __tablename__ = "cve_cache"
    key = db.Column(db.String(300), primary_key=True)
    data = db.Column(db.JSON, nullable=False)
    fetched_at = db.Column(db.DateTime, default=utcnow)
