import os
import tempfile
import threading
import time
import traceback
import xml.etree.ElementTree as ET
from collections import Counter

from flask import Blueprint, Response, current_app, g, jsonify, request

from . import cve, report, scanner
from .auth import err, login_required
from .models import Scan, db, utcnow
from .validators import ValidationError, parse_ports, parse_target

bp = Blueprint("scans", __name__, url_prefix="/api/scans")
SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _owned(sid):
    s = db.session.get(Scan, sid)
    return s if s and s.user_id == g.uid else None


def summarize(hosts, partial):
    sev, ports, osn, kev, low, open_ports = Counter(), Counter(), Counter(), 0, 0, 0
    for h in hosts:
        osn[h["os"] or "Unknown"] += 1
        for p in h["ports"]:
            open_ports += 1
            ports[f'{p["port"]}/{p["proto"]}'] += 1
            for c in p["cves"]:
                if p["cve_confidence"] == "low":
                    low += 1  # keyword matches never inflate headline numbers
                    continue
                sev[c["severity"] if c["severity"] in SEV else "UNKNOWN"] += 1
                kev += 1 if c["kev"] else 0
    return {"hosts_up": len(hosts), "open_ports": open_ports, "cve_findings": sum(sev.values()),
            "severity": {k: sev.get(k, 0) for k in SEV}, "kev": kev, "possible_cves": low,
            "top_ports": [{"label": k, "count": v} for k, v in ports.most_common(8)],
            "os": [{"label": k, "count": v} for k, v in osn.most_common(6)],
            "cve_partial": partial}


def _run(app, sid):
    with app.app_context():
        scan = db.session.get(Scan, sid)
        state, xml = None, None

        def prog(pct, phase):
            scan.progress, scan.phase = min(pct, 99), phase
            db.session.commit()

        try:
            scan.status, scan.started_at = "running", utcnow()
            prog(1, "Starting nmap")
            fd, xml = tempfile.mkstemp(suffix=".xml")
            os.close(fd)
            cmd = scanner.build_cmd(scan.nmap_target, scan.profile, scan.ports,
                                    scan.timeout_min, scan.assume_up, xml)
            rc, state, tail = scanner.run_nmap(sid, cmd, scan.timeout_min, prog)
            if state["cancel"]:
                scan.status, scan.phase = "cancelled", "Cancelled"
                return
            try:
                result = scanner.parse_xml(xml)
            except ET.ParseError:
                raise RuntimeError("nmap failed: " + " | ".join(tail[-3:]))
            if rc != 0 and not result["hosts"] and not state["timeout"]:
                raise RuntimeError("nmap failed: " + " | ".join(tail[-3:]))
            result["stats"]["timed_out"] = state["timeout"]

            services = {}
            for h in result["hosts"]:
                for p in h["ports"]:
                    if p["cpes"] or (p["product"] and p["version"]):
                        key = (p["cpes"][0] if p["cpes"] else None, p["product"], p["version"])
                        services.setdefault(key, []).append(p)
            deadline = time.time() + current_app.config["CVE_BUDGET_SEC"]
            partial = False
            for i, (key, plist) in enumerate(services.items(), 1):
                if state["cancel"]:
                    scan.status, scan.phase = "cancelled", "Cancelled"
                    return
                if time.time() > deadline:
                    partial = True
                    break
                prog(85 + int(14 * i / len(services)), f"CVE lookup {i}/{len(services)}")
                info = cve.lookup(*key)
                for p in plist:
                    p["cves"], p["cve_total"], p["cve_confidence"] = info["cves"], info["total"], info["confidence"]
            result["summary"] = summarize(result["hosts"], partial)
            scan.result, scan.status = result, "completed"
            scan.progress, scan.phase = 100, "Done"
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            db.session.rollback()
            scan.status, scan.error = "failed", str(e)[:500]
        finally:
            scan.finished_at = utcnow()
            db.session.commit()
            scanner.RUNNING.pop(sid, None)
            if xml and os.path.exists(xml):
                os.remove(xml)


@bp.post("")
@login_required
def create():
    d, cfg = request.get_json(silent=True) or {}, current_app.config
    if d.get("authorized") is not True:
        return err("Confirm you are authorised to scan this target")
    try:
        label, nmap_target = parse_target(d.get("target"), cfg["MAX_HOSTS"])
        ports = parse_ports(d.get("ports"))
    except ValidationError as e:
        return err(str(e))
    profile = d.get("profile", "moderate")
    if profile not in scanner.PROFILES:
        return err("Unknown profile")
    try:
        minutes = int(d.get("timeout_min") or scanner.PROFILES[profile]["minutes"])
    except (TypeError, ValueError):
        return err("Time limit must be a number of minutes")
    if not 1 <= minutes <= cfg["MAX_TIMEOUT_MIN"]:
        return err(f"Time limit must be 1-{cfg['MAX_TIMEOUT_MIN']} minutes")
    active = Scan.query.filter(Scan.status.in_(("queued", "running"))).all()
    if any(s.user_id == g.uid for s in active):
        return err("You already have a scan running", 429)
    if len(active) >= cfg["MAX_CONCURRENT"]:
        return err("Server is busy. Try again shortly", 429)
    scan = Scan(user_id=g.uid, target=label, nmap_target=nmap_target, profile=profile, ports=ports,
                timeout_min=minutes, assume_up=bool(d.get("assume_up")), authorized=True,
                source_ip=request.remote_addr, status="queued")
    db.session.add(scan)
    db.session.commit()
    threading.Thread(target=_run, args=(current_app._get_current_object(), scan.id), daemon=True).start()
    return jsonify(scan.to_dict()), 201


@bp.get("")
@login_required
def history():
    rows = Scan.query.filter_by(user_id=g.uid).order_by(Scan.id.desc()).limit(50).all()
    return jsonify([s.to_dict() for s in rows])


@bp.get("/<int:sid>")
@login_required
def detail(sid):
    s = _owned(sid)
    return jsonify(s.to_dict(full=s.status == "completed")) if s else err("Not found", 404)


@bp.post("/<int:sid>/cancel")
@login_required
def cancel(sid):
    s = _owned(sid)
    if not s:
        return err("Not found", 404)
    st = scanner.RUNNING.get(sid)
    if not st:
        return err("Scan is not running", 409)
    st["stop"]("cancel")
    return jsonify(ok=True)


@bp.get("/<int:sid>/report.pdf")
@login_required
def pdf(sid):
    s = _owned(sid)
    if not s:
        return err("Not found", 404)
    if s.status != "completed":
        return err("Report is available once the scan completes", 409)
    return Response(report.build_pdf(s, g.username), mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="netrec-scan-{s.id}.pdf"'})
