"""NVD API 2.0 client with DB cache and rate limiting."""
import re
import threading
import time
from datetime import datetime, timedelta

import requests
from flask import current_app

from .models import CVECache, db, utcnow

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TTL = timedelta(days=7)
_lock = threading.Lock()
_last = [0.0]


def _get(params, api_key):
    interval = 0.7 if api_key else 6.5  # NVD: 50 req/30s with key, 5 req/30s without
    headers = {"apiKey": api_key} if api_key else {}
    with _lock:  # serialise: all scans share one rate limit
        for attempt in range(3):
            wait = interval - (time.time() - _last[0])
            if wait > 0:
                time.sleep(wait)
            try:
                r = requests.get(NVD, params=params, headers=headers, timeout=30)
            except requests.RequestException:
                r = None
            _last[0] = time.time()
            if r is not None and r.status_code == 200:
                return r.json()
            if r is not None and r.status_code not in (403, 429, 503):
                return {}  # definitive "no" (e.g. unknown CPE): safe to cache as empty
            time.sleep(interval * 2 * (attempt + 1))
    return None  # NVD unreachable: do NOT cache


def _parse(data):
    out = []
    for v in (data or {}).get("vulnerabilities", []):
        c = v["cve"]
        score, sev = None, "UNKNOWN"
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = c.get("metrics", {}).get(k)
            if m:
                score = m[0]["cvssData"]["baseScore"]
                sev = (m[0]["cvssData"].get("baseSeverity") or m[0].get("baseSeverity") or "UNKNOWN").upper()
                break
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append({"id": c["id"], "score": score, "severity": sev,
                    "published": c.get("published", "")[:10], "summary": desc[:400],
                    "kev": bool(c.get("cisaExploitAdd"))})
    out.sort(key=lambda x: x["score"] or 0, reverse=True)
    return out


def _variants(cpe):
    yield cpe
    p = cpe.split(":")  # NVD stores OpenSSH 7.6p1 as version "7.6", update "p1"
    m = re.match(r"^(\d+(?:\.\d+)*)([a-z]\d*)$", p[5])
    if m:
        q = p[:]
        q[5], q[6] = m.group(1), m.group(2)
        yield ":".join(q)


def lookup(cpe, product, version):
    """-> {"cves": [...top 25...], "total": n, "confidence": "high"|"low"}"""
    key = (cpe or f"kw:{product}:{version}").lower()[:300]
    row = db.session.get(CVECache, key)
    if row and utcnow() - row.fetched_at < TTL:
        return row.data
    api_key = current_app.config["NVD_API_KEY"]
    data, conf, reachable = None, "high", False
    if cpe:
        for v in _variants(cpe):
            r = _get({"cpeName": v, "resultsPerPage": 200}, api_key)
            reachable = reachable or r is not None
            if r and r.get("vulnerabilities"):
                data = r
                break
    if data is None and product and version:
        r = _get({"keywordSearch": f"{product} {version}", "resultsPerPage": 50}, api_key)
        reachable = reachable or r is not None
        if r and r.get("vulnerabilities"):
            data, conf = r, "low"  # keyword hits are noisy: flagged, excluded from headline counts
    cves = _parse(data)
    out = {"cves": cves[:25], "total": (data or {}).get("totalResults", len(cves)), "confidence": conf}
    if reachable:
        db.session.merge(CVECache(key=key, data=out, fetched_at=utcnow()))
        db.session.commit()
    return out
