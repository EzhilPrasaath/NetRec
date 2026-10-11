import os


class Config:
    SECRET_KEY = os.environ["SECRET_KEY"]
    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("COOKIE_SECURE") == "1"
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    MAX_HOSTS = 256          # largest CIDR accepted (/24)
    MAX_TIMEOUT_MIN = 60     # hard ceiling on a scan's time limit
    MAX_CONCURRENT = 2       # scans running at once, all users
    CVE_BUDGET_SEC = 240     # max time spent on CVE lookups per scan
