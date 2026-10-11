import ipaddress
import re
import socket

HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


class ValidationError(ValueError):
    pass


def _check_ip(ip):
    if ip.version != 4:
        raise ValidationError("Only IPv4 targets are supported in this version")
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise ValidationError("Loopback, link-local, multicast and reserved addresses are blocked")


def parse_target(raw, max_hosts):
    """Return (label, nmap_target). Never lets user text reach nmap as an option."""
    t = (raw or "").strip()
    if not t or len(t) > 100 or t.startswith("-"):
        raise ValidationError("Enter an IP, a CIDR range (192.168.1.0/24) or a hostname")
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        net = None
    if net is not None:
        _check_ip(net.network_address)
        if net.num_addresses > max_hosts:
            raise ValidationError(f"Range too large. Maximum is {max_hosts} addresses (/24)")
        return str(net), str(net)
    if not HOST_RE.match(t):
        raise ValidationError("Enter an IP, a CIDR range (192.168.1.0/24) or a hostname")
    try:
        ip = ipaddress.ip_address(socket.getaddrinfo(t, None, socket.AF_INET)[0][4][0])
    except (socket.gaierror, IndexError):
        raise ValidationError("Hostname does not resolve")
    _check_ip(ip)
    return t, str(ip)  # scan the IP we validated, not a name that could re-resolve


def parse_ports(raw):
    p = (raw or "").strip().replace(" ", "")
    if not p:
        return None
    if p.lower() == "all":
        return "1-65535"
    if len(p) > 200 or not PORTS_RE.match(p):
        raise ValidationError("Ports look like 22,80,443 or 1-1024 or 22,8000-8100")
    for part in p.split(","):
        lo, _, hi = part.partition("-")
        lo, hi = int(lo), int(hi or lo)
        if not 1 <= lo <= hi <= 65535:
            raise ValidationError("Ports must be 1-65535 and ranges must ascend")
    return p
