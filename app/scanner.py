"""nmap wrapper: build a safe command, stream progress, parse XML."""
import os
import re
import signal
import subprocess
import threading
import xml.etree.ElementTree as ET

PRIV = os.getenv("NMAP_PRIVILEGED") == "1"
RUNNING = {}  # scan_id -> {"proc", "stop", "cancel", "timeout"}

PROFILES = {
    "fast": dict(ports=["--top-ports", "100"], os=False, minutes=5,
                 extra=["-sV", "--version-intensity", "0", "--max-retries", "1"]),
    "moderate": dict(ports=["--top-ports", "1000"], os=True, minutes=15,
                     extra=["-sV", "--version-intensity", "5", "--max-retries", "2"]),
    "deep": dict(ports=["-p", "1-65535"], os=True, minutes=45,
                 extra=["-sV", "--version-all", "--max-retries", "2"]),
}

# nmap prints "<label> Timing: About NN% done"; map each label onto a slice of 0-85%
PHASES = {
    "Ping Scan": (0, 8, "Host discovery"), "ARP Ping Scan": (0, 8, "Host discovery"),
    "SYN Stealth Scan": (8, 50, "Port scan"), "Connect Scan": (8, 50, "Port scan"),
    "Service scan": (50, 82, "Service / version detection"), "NSE": (82, 85, "Scripts"),
}
PCT_RE = re.compile(r"About ([\d.]+)% done")


def build_cmd(target, profile, ports, minutes, assume_up, xml_path):
    p = PROFILES[profile]
    cmd = ["nmap", "-sS" if PRIV else "-sT", "-T4"]
    cmd += ["-p", ports] if ports else p["ports"]
    cmd += p["extra"]
    if p["os"] and PRIV:
        cmd += ["-O", "--osscan-guess"]
    if assume_up:
        cmd.append("-Pn")
    cmd += ["--host-timeout", f"{minutes}m", "--stats-every", "2s", "-oX", xml_path, target]
    return cmd  # list form + validated target: no shell, no option injection


def run_nmap(scan_id, cmd, minutes, on_progress):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    state = {"proc": proc, "cancel": False, "timeout": False}

    def stop(reason):
        state[reason] = True
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)  # nmap flushes partial XML on SIGINT
            t = threading.Timer(15, lambda: proc.poll() is None and proc.kill())
            t.daemon = True
            t.start()

    state["stop"] = stop
    RUNNING[scan_id] = state
    wd = threading.Timer(minutes * 60, stop, args=("timeout",))
    wd.daemon = True
    wd.start()
    floor, tail = 0, []
    try:
        for line in proc.stdout:
            line = line.strip()
            if line:
                tail = (tail + [line])[-6:]
            if "Timing: About" in line:
                label = line.split(" Timing")[0]
                m = PCT_RE.search(line)
                if label in PHASES and m:
                    lo, hi, name = PHASES[label]
                    floor = max(floor, lo + int((hi - lo) * float(m.group(1)) / 100))
                    on_progress(max(floor, 1), name)
            elif "Initiating OS detection" in line:
                floor = max(floor, 83)
                on_progress(floor, "OS detection")
        proc.wait()
    finally:
        wd.cancel()
    return proc.returncode, state, tail


def to_cpe23(c):
    """nmap emits CPE 2.2 URIs (cpe:/a:vendor:product:ver); NVD wants 2.3 strings."""
    if not c or not c.startswith("cpe:/"):
        return None
    parts = c[5:].split(":")
    if len(parts) < 4 or not parts[3]:
        return None
    return "cpe:2.3:" + ":".join(parts + ["*"] * (11 - len(parts)))


def parse_xml(path):
    root = ET.parse(path).getroot()
    hosts = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        host = {"ip": None, "mac": None, "vendor": None, "hostname": None,
                "os": None, "os_accuracy": None, "ports": [], "not_open": 0,
                "reason": st.get("reason")}  # e.g. echo-reply, arp-response, user-set (-Pn)
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                host["ip"] = a.get("addr")
            elif a.get("addrtype") == "mac":
                host["mac"], host["vendor"] = a.get("addr"), a.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            host["hostname"] = hn.get("name")
        om = h.find("os/osmatch")
        if om is not None:
            host["os"], host["os_accuracy"] = om.get("name"), int(om.get("accuracy", 0))
        for ex in h.findall("ports/extraports"):
            host["not_open"] += int(ex.get("count", 0))
        for p in h.findall("ports/port"):
            if p.find("state").get("state") != "open":
                host["not_open"] += 1
                continue
            svc = p.find("service")
            g = (lambda k: svc.get(k)) if svc is not None else (lambda k: None)
            cpes = [c for c in (to_cpe23(x.text) for x in svc.findall("cpe")) if c] if svc is not None else []
            host["ports"].append({
                "port": int(p.get("portid")), "proto": p.get("protocol"),
                "service": g("name"), "product": g("product"), "version": g("version"),
                "extra": g("extrainfo"), "cpes": cpes, "cves": [], "cve_total": 0,
                "cve_confidence": None,
            })
        host["ports"].sort(key=lambda x: x["port"])
        hosts.append(host)
    fin = root.find("runstats/finished")
    hs = root.find("runstats/hosts")
    stats = {"elapsed": float(fin.get("elapsed", 0)) if fin is not None else None,
             "total": int(hs.get("total", 0)) if hs is not None else len(hosts),
             "up": len(hosts), "timed_out": False}
    return {"hosts": hosts, "stats": stats}
