#!/usr/bin/env python3
"""
Enhanced Multi-Protocol Scanner (mpscan)
========================================

A dependency-free (Python standard library only) network reconnaissance tool.

Features
--------
* Multi-protocol service enumeration / banner grabbing
  (HTTP/S, SSH, FTP, SMTP, POP3, IMAP, Telnet, MySQL, PostgreSQL, MSSQL,
   Redis, SMB, RDP, and a generic fallback probe).
* Lightweight version detection + heuristic vulnerability *hints*.
* TTL-based OS fingerprinting, combined with banner evidence.
* DNS resolution + reverse DNS.
* Output: JSON, CSV, nmap-like XML, and a styled HTML report.
* Stealth: global rate limiting + per-connection jitter.
* SOCKS5 / SOCKS4 / HTTP-CONNECT proxy support (hand-rolled, no PySocks).

LEGAL / ETHICAL NOTE
--------------------
Only scan systems you own or are explicitly authorized to test. Unauthorized
scanning may be illegal in your jurisdiction. You are responsible for your use
of this tool.
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import platform
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html import escape
from xml.dom import minidom

# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #

# Curated "common ports" -> default service guess.
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-smb",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "smtp-sub", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5060: "sip", 5432: "postgres", 5900: "vnc", 5985: "winrm",
    6379: "redis", 6443: "kube-api", 7001: "weblogic", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch", 9300: "elastic",
    11211: "memcached", 27017: "mongodb",
}

# Ports that speak TLS immediately (wrap the socket before app-layer probe).
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 6443}

# Underlying protocol for an implicit-TLS port.
TLS_INNER = {443: "http", 8443: "http", 6443: "http",
             993: "imap", 995: "pop3", 465: "smtp", 636: "ldap"}

DEFAULT_PORTS = sorted(COMMON_PORTS.keys())
USER_AGENT = "mpscan/1.0"


# --------------------------------------------------------------------------- #
# Rate limiting + jitter (stealth)                                            #
# --------------------------------------------------------------------------- #

class RateLimiter:
    """Global token-paced limiter with optional random jitter.

    `rate` is max connection attempts per second (0 = unlimited).
    `jitter` adds a uniform random sleep in [0, jitter] seconds per attempt.
    """

    def __init__(self, rate: float = 0.0, jitter: float = 0.0):
        self.min_interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self.jitter = max(0.0, jitter)
        self._lock = threading.Lock()
        self._next_slot = 0.0

    def wait(self) -> None:
        if self.min_interval > 0:
            with self._lock:
                now = time.monotonic()
                start = max(now, self._next_slot)
                self._next_slot = start + self.min_interval
                delay = start - now
            if delay > 0:
                time.sleep(delay)
        if self.jitter > 0:
            time.sleep(random.uniform(0, self.jitter))


# --------------------------------------------------------------------------- #
# Proxy support (SOCKS5 / SOCKS4 / HTTP CONNECT) -- hand-rolled, no deps      #
# --------------------------------------------------------------------------- #

class ProxyConfig:
    def __init__(self, scheme: str, host: str, port: int,
                 username: str | None = None, password: str | None = None):
        self.scheme = scheme.lower()
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    @classmethod
    def parse(cls, url: str | None) -> "ProxyConfig | None":
        if not url:
            return None
        m = re.match(
            r"^(socks5|socks4|http)://"
            r"(?:([^:@/]+)(?::([^@/]*))?@)?"
            r"([^:/]+):(\d+)/?$", url, re.I)
        if not m:
            raise ValueError(
                "proxy must look like scheme://[user:pass@]host:port "
                "(scheme = socks5|socks4|http)")
        scheme, user, pw, host, port = m.groups()
        return cls(scheme, host, int(port), user, pw)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("proxy closed connection during handshake")
        buf += chunk
    return buf


def _proxy_socks5(sock, dst_host, dst_port, proxy: ProxyConfig):
    if proxy.username:
        sock.sendall(b"\x05\x02\x00\x02")  # offer no-auth + user/pass
    else:
        sock.sendall(b"\x05\x01\x00")
    ver, method = _recv_exact(sock, 2)
    if ver != 5:
        raise ConnectionError("bad SOCKS5 version from proxy")
    if method == 0x02:
        u = (proxy.username or "").encode()
        p = (proxy.password or "").encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        _, status = _recv_exact(sock, 2)
        if status != 0:
            raise ConnectionError("SOCKS5 auth failed")
    elif method != 0x00:
        raise ConnectionError("SOCKS5 proxy demanded an unsupported auth method")
    host_b = dst_host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack(">H", dst_port)
    sock.sendall(req)
    reply = _recv_exact(sock, 4)
    if reply[1] != 0x00:
        raise ConnectionError(f"SOCKS5 connect rejected (code {reply[1]})")
    atyp = reply[3]
    if atyp == 0x01:
        _recv_exact(sock, 4)
    elif atyp == 0x03:
        ln = _recv_exact(sock, 1)[0]
        _recv_exact(sock, ln)
    elif atyp == 0x04:
        _recv_exact(sock, 16)
    _recv_exact(sock, 2)  # bound port


def _proxy_socks4(sock, dst_host, dst_port, proxy: ProxyConfig):
    try:
        ip = socket.inet_aton(dst_host)
        domain = b""
    except OSError:
        # SOCKS4a: let proxy resolve; use 0.0.0.x sentinel.
        ip = b"\x00\x00\x00\x01"
        domain = dst_host.encode() + b"\x00"
    user = (proxy.username or "").encode()
    sock.sendall(b"\x04\x01" + struct.pack(">H", dst_port) + ip + user + b"\x00" + domain)
    resp = _recv_exact(sock, 8)
    if resp[1] != 0x5a:
        raise ConnectionError(f"SOCKS4 connect rejected (code {resp[1]})")


def _proxy_http_connect(sock, dst_host, dst_port, proxy: ProxyConfig):
    req = f"CONNECT {dst_host}:{dst_port} HTTP/1.1\r\nHost: {dst_host}:{dst_port}\r\n"
    if proxy.username:
        import base64
        token = base64.b64encode(
            f"{proxy.username}:{proxy.password or ''}".encode()).decode()
        req += f"Proxy-Authorization: Basic {token}\r\n"
    req += "\r\n"
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
        if len(resp) > 65536:
            break
    status = resp.split(b"\r\n", 1)[0]
    if b" 200 " not in status and not status.endswith(b" 200"):
        raise ConnectionError(f"HTTP proxy refused: {status.decode(errors='replace')}")


def open_connection(host: str, port: int, timeout: float,
                    proxy: ProxyConfig | None) -> socket.socket:
    """Return a connected TCP socket, optionally tunneled through a proxy."""
    if proxy is None:
        return socket.create_connection((host, port), timeout=timeout)

    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        if proxy.scheme == "socks5":
            _proxy_socks5(sock, host, port, proxy)
        elif proxy.scheme == "socks4":
            _proxy_socks4(sock, host, port, proxy)
        elif proxy.scheme == "http":
            _proxy_http_connect(sock, host, port, proxy)
        else:
            raise ValueError(f"unknown proxy scheme {proxy.scheme}")
    except Exception:
        sock.close()
        raise
    return sock


# --------------------------------------------------------------------------- #
# DNS                                                                         #
# --------------------------------------------------------------------------- #

def resolve_host(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except OSError:
        return None


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# OS fingerprinting (TTL based, via system ping -- no raw sockets needed)     #
# --------------------------------------------------------------------------- #

def _ping_ttl(host: str, timeout: float = 2.0) -> int | None:
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        # -c 1 single probe; -W timeout secs (Linux). macOS ignores -W gracefully.
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout + 2)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    text = (out.stdout or "") + (out.stderr or "")
    m = re.search(r"ttl[=\s]*(\d+)", text, re.I)
    return int(m.group(1)) if m else None


def os_from_ttl(ttl: int | None) -> tuple[str, int | None]:
    """Map an observed TTL to a likely original-TTL OS family."""
    if ttl is None:
        return ("unknown", None)
    # Pick the smallest common initial TTL >= observed (accounts for hops).
    for initial, name in ((64, "Linux/Unix/macOS"),
                          (128, "Windows"),
                          (255, "Network device / Solaris / *BSD")):
        if ttl <= initial:
            return (name, initial)
    return ("unknown", None)


# --------------------------------------------------------------------------- #
# Banner helpers                                                              #
# --------------------------------------------------------------------------- #

def _clean(data: bytes, limit: int = 600) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    text = "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "." for ch in text)
    text = text.strip()
    if len(text) > limit:
        text = text[:limit] + "...[truncated]"
    return text


def _recv_some(sock, n=4096, timeout=4.0) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(n)
    except (socket.timeout, OSError):
        return b""


def _recv_all(sock, limit=65536, timeout=4.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError):
        pass
    return buf


# --------------------------------------------------------------------------- #
# Protocol-specific grabbers                                                  #
#   each returns dict: {banner, version, extra}                              #
# --------------------------------------------------------------------------- #

def grab_generic(sock, host, port):
    data = _recv_some(sock, timeout=3.0)
    if not data:
        # Some services are silent until spoken to -- try a tiny HTTP poke.
        try:
            sock.sendall(b"\r\n")
            data = _recv_some(sock, timeout=2.0)
        except OSError:
            pass
    return {"banner": _clean(data), "version": None, "extra": {}}


def grab_http(sock, host, port):
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
           f"Accept: */*\r\nConnection: close\r\n\r\n")
    try:
        sock.sendall(req.encode())
    except OSError:
        return {"banner": "", "version": None, "extra": {}}
    raw = _recv_all(sock, limit=131072, timeout=5.0)
    text = raw.decode("latin-1", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    status = head.split("\r\n", 1)[0] if head else ""
    headers = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    title = None
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    server = headers.get("server")
    extra = {"status": status.strip(), "server": server, "title": title}
    if "x-powered-by" in headers:
        extra["x_powered_by"] = headers["x-powered-by"]
    banner_bits = [b for b in (status.strip(), f"Server: {server}" if server else None,
                              f"Title: {title}" if title else None) if b]
    return {"banner": " | ".join(banner_bits) or _clean(raw),
            "version": server, "extra": extra}


def grab_ssh(sock, host, port):
    data = _recv_some(sock, timeout=4.0)
    banner = _clean(data)
    version = None
    m = re.search(r"SSH-[\d.]+-(\S+)", banner)
    if m:
        version = m.group(1)
    return {"banner": banner, "version": version, "extra": {}}


def grab_line(sock, host, port):
    """FTP/SMTP/POP3/IMAP/Telnet: server greets first."""
    data = _recv_some(sock, timeout=4.0)
    return {"banner": _clean(data), "version": None, "extra": {}}


def grab_smtp(sock, host, port):
    greet = _recv_some(sock, timeout=4.0)
    extra = {}
    try:
        sock.sendall(b"EHLO mpscan.local\r\n")
        ehlo = _recv_some(sock, timeout=3.0)
        if ehlo:
            extra["ehlo"] = _clean(ehlo, 400)
    except OSError:
        pass
    return {"banner": _clean(greet), "version": None, "extra": extra}


def grab_mysql(sock, host, port):
    data = _recv_some(sock, timeout=4.0)
    version = None
    extra = {}
    if len(data) > 5 and data[4] in (9, 10):
        try:
            end = data.index(b"\x00", 5)
            version = data[5:end].decode("latin-1", errors="replace")
        except ValueError:
            pass
    elif b"is not allowed to connect" in data or b"Host" in data[:60]:
        extra["note"] = "server reachable but rejected host (access control active)"
        m = re.search(rb"(\d+\.\d+\.\d+[\w.-]*)", data)
        if m:
            version = m.group(1).decode()
    return {"banner": version or _clean(data, 200),
            "version": version, "extra": extra}


def grab_redis(sock, host, port):
    extra = {}
    version = None
    try:
        sock.sendall(b"INFO server\r\n")
    except OSError:
        return {"banner": "", "version": None, "extra": {}}
    data = _recv_all(sock, limit=8192, timeout=3.0)
    text = data.decode("latin-1", errors="replace")
    if "redis_version:" in text:
        extra["auth"] = "NONE (unauthenticated access succeeded)"
        m = re.search(r"redis_version:([\w.]+)", text)
        if m:
            version = m.group(1)
    elif "NOAUTH" in text:
        extra["auth"] = "required"
    return {"banner": f"redis_version:{version}" if version else _clean(data, 200),
            "version": version, "extra": extra}


def build_smb1_negotiate() -> bytes:
    dialects = [b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0",
                b"Windows for Workgroups 3.1a", b"LM1.2X002",
                b"LANMAN2.1", b"NT LM 0.12"]
    body = b"".join(b"\x02" + d + b"\x00" for d in dialects)
    smb = (
        b"\xffSMB" b"\x72"            # protocol + Negotiate
        b"\x00\x00\x00\x00"          # status
        b"\x18" b"\x01\x28"          # flags / flags2
        b"\x00\x00"                  # pid high
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # signature
        b"\x00\x00" b"\x00\x00"      # reserved / tid
        b"\xff\xfe" b"\x00\x00" b"\x00\x00"  # pid / uid / mid
        b"\x00"                      # word count
        + struct.pack("<H", len(body)) + body
    )
    return b"\x00\x00" + struct.pack(">H", len(smb)) + smb


def grab_smb(sock, host, port):
    extra = {}
    try:
        sock.sendall(build_smb1_negotiate())
    except OSError:
        return {"banner": "", "version": None, "extra": {}}
    data = _recv_some(sock, n=1024, timeout=4.0)
    if b"\xffSMB" in data:
        extra["smb_v1"] = "enabled"
        banner = "SMBv1 negotiation succeeded (SMBv1 enabled)"
    elif b"\xfeSMB" in data:
        extra["smb_v2plus"] = "enabled"
        banner = "SMB2+ responded"
    else:
        banner = _clean(data, 120) or "SMB port open (no negotiate response)"
    return {"banner": banner, "version": None, "extra": extra}


def grab_rdp(sock, host, port):
    packet = bytes.fromhex("0300001300eee0000000000001000800030000000"[:38])
    # Correct, well-formed 19-byte X.224 connection request:
    packet = bytes([0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0,
                    0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00])
    extra = {}
    try:
        sock.sendall(packet)
    except OSError:
        return {"banner": "", "version": None, "extra": {}}
    data = _recv_some(sock, n=512, timeout=4.0)
    banner = "RDP service"
    if len(data) >= 6 and data[5] == 0xd0:
        banner = "RDP (X.224 connection confirmed)"
        # Optional RDP negotiation response at offset 11.
        if len(data) >= 19 and data[11] == 0x02:
            proto = struct.unpack("<I", data[15:19])[0]
            sel = {0: "Standard RDP Security", 1: "TLS",
                   2: "CredSSP / NLA", 8: "RDSTLS"}.get(proto, f"0x{proto:x}")
            extra["selected_protocol"] = sel
            banner += f" | {sel}"
            if proto == 0:
                extra["nla"] = "NOT required (legacy RDP security)"
        elif len(data) >= 12 and data[11] == 0x03:
            extra["negotiation"] = "failure (NLA likely required)"
            banner += " | negotiation failure (NLA likely enforced)"
    return {"banner": banner, "version": None, "extra": extra}


GRABBERS = {
    "http": grab_http, "https": grab_http, "http-alt": grab_http,
    "http-proxy": grab_http, "https-alt": grab_http, "kube-api": grab_http,
    "ssh": grab_ssh,
    "ftp": grab_line, "telnet": grab_line, "pop3": grab_line,
    "imap": grab_line, "imaps": grab_line, "pop3s": grab_line,
    "smtp": grab_smtp, "smtp-sub": grab_smtp, "smtps": grab_smtp,
    "mysql": grab_mysql,
    "redis": grab_redis,
    "smb": grab_smb, "netbios-smb": grab_smb,
    "rdp": grab_rdp,
}


# --------------------------------------------------------------------------- #
# TLS wrap helper                                                             #
# --------------------------------------------------------------------------- #

def tls_wrap(sock, host):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ss = ctx.wrap_socket(sock, server_hostname=host)
    except (ssl.SSLError, OSError):
        ss = ctx.wrap_socket(sock)  # retry without SNI
    info = {"tls_version": ss.version(),
            "cipher": ss.cipher()[0] if ss.cipher() else None}
    return ss, info


# --------------------------------------------------------------------------- #
# Heuristic vulnerability hints (advisory only)                              #
# --------------------------------------------------------------------------- #

def _ver_tuple(s: str):
    nums = re.findall(r"\d+", s)
    return tuple(int(n) for n in nums[:3]) if nums else ()


def vuln_hints(service, banner, version, extra) -> list[str]:
    hints: list[str] = []
    b = (banner or "").lower()
    v = (version or "")

    if service == "ssh":
        m = re.search(r"openssh[_\- ]?([\d.]+)", b)
        if m and _ver_tuple(m.group(1)) and _ver_tuple(m.group(1)) < (8, 0):
            hints.append(f"OpenSSH {m.group(1)} is dated; review against current "
                         "CVEs (e.g. user-enum / auth issues in older branches).")

    if service in ("http", "https", "http-alt", "http-proxy", "https-alt"):
        srv = (extra.get("server") or "").lower()
        am = re.search(r"apache/([\d.]+)", srv)
        if am and _ver_tuple(am.group(1)) < (2, 4, 50):
            hints.append(f"Apache {am.group(1)} predates 2.4.50; check for path-"
                         "traversal / RCE (CVE-2021-41773 family).")
        nm = re.search(r"nginx/([\d.]+)", srv)
        if nm and _ver_tuple(nm.group(1)) < (1, 20):
            hints.append(f"nginx {nm.group(1)} is old; verify against advisories.")
        if extra.get("x_powered_by"):
            hints.append(f"Leaks stack via X-Powered-By: {extra['x_powered_by']}.")

    if service in ("smb", "netbios-smb") and extra.get("smb_v1") == "enabled":
        hints.append("SMBv1 enabled — exposed to EternalBlue (MS17-010) class "
                     "issues; disable SMBv1.")

    if service == "redis" and extra.get("auth", "").startswith("NONE"):
        hints.append("Redis is reachable without authentication — full data/"
                     "command access; bind to localhost and set requirepass.")

    if service == "telnet" and banner:
        hints.append("Telnet transmits credentials in cleartext; prefer SSH.")

    if service in ("mysql", "postgres", "mssql", "mongodb", "elasticsearch") \
            and "is not allowed" not in b and banner:
        hints.append(f"{service} exposed on the network; restrict to trusted hosts.")

    tls_ver = (extra.get("tls_version") or "")
    if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3"):
        hints.append(f"Weak transport: {tls_ver} negotiated; disable legacy TLS/SSL.")

    if extra.get("nla", "").startswith("NOT"):
        hints.append("RDP allows legacy security (NLA not enforced) — enable NLA.")

    return hints


# --------------------------------------------------------------------------- #
# Core scanning                                                               #
# --------------------------------------------------------------------------- #

def detect_service(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


def scan_port(host: str, port: int, args, limiter: RateLimiter, proxy):
    limiter.wait()
    service = detect_service(port)
    result = {"port": port, "protocol": "tcp", "state": "closed",
              "service": service, "banner": "", "version": None,
              "vuln_hints": [], "extra": {}}
    sock = None
    try:
        sock = open_connection(host, port, args.timeout, proxy)
        result["state"] = "open"
        extra = {}

        if port in TLS_PORTS:
            try:
                sock, tinfo = tls_wrap(sock, host)
                extra.update(tinfo)
                service = TLS_INNER.get(port, service)
                result["service"] = COMMON_PORTS.get(port, service)
            except Exception as exc:  # noqa: BLE001
                extra["tls_error"] = str(exc)[:120]

        if not args.no_banner:
            grabber = GRABBERS.get(service, grab_generic)
            try:
                info = grabber(sock, host, port)
            except Exception as exc:  # noqa: BLE001
                info = {"banner": f"(grab error: {exc})", "version": None, "extra": {}}
            result["banner"] = info.get("banner", "")
            result["version"] = info.get("version")
            extra.update(info.get("extra", {}))

        result["extra"] = extra
        result["vuln_hints"] = vuln_hints(service, result["banner"],
                                          result["version"], extra)
    except (socket.timeout, ConnectionRefusedError):
        result["state"] = "closed"
    except (OSError, ConnectionError):
        result["state"] = "filtered"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if result["state"] == "open" or args.show_closed:
        return result
    return None


def scan_host(ip: str, origin: str | None, ports, args, limiter, proxy):
    host_rec = {
        "host": ip,
        "input": origin,
        "hostname": None,
        "os_guess": "unknown",
        "ttl": None,
        "ports": [],
    }

    if not args.no_dns:
        host_rec["hostname"] = reverse_dns(ip)

    if not args.no_os:
        ttl = _ping_ttl(ip, timeout=args.timeout)
        os_name, _initial = os_from_ttl(ttl)
        host_rec["ttl"] = ttl
        host_rec["os_guess"] = os_name

    workers = max(1, args.threads)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(scan_port, ip, p, args, limiter, proxy): p for p in ports}
        for fut in as_completed(futs):
            res = fut.result()
            if res is not None:
                host_rec["ports"].append(res)

    host_rec["ports"].sort(key=lambda r: r["port"])

    # Combine OS guess with banner evidence.
    banners = " ".join(p["banner"].lower() for p in host_rec["ports"])
    if "windows" in banners or any(p["service"] in ("rdp", "smb", "msrpc")
                                  and p["state"] == "open" for p in host_rec["ports"]):
        if host_rec["os_guess"] == "unknown":
            host_rec["os_guess"] = "Windows (banner evidence)"
        elif "Windows" not in host_rec["os_guess"]:
            host_rec["os_guess"] += " (note: Windows-typical services present)"
    if any(k in banners for k in ("ubuntu", "debian", "centos", "openssh")):
        if host_rec["os_guess"] == "unknown":
            host_rec["os_guess"] = "Linux/Unix (banner evidence)"

    return host_rec


# --------------------------------------------------------------------------- #
# Target / port expansion                                                     #
# --------------------------------------------------------------------------- #

def expand_targets(specs: list[str]) -> list[tuple[str, str | None]]:
    """Return list of (ip, original_input). Hostnames are resolved."""
    out: list[tuple[str, str | None]] = []
    seen = set()
    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        try:
            net = ipaddress.ip_network(spec, strict=False)
            hosts = (net.hosts() if net.num_addresses > 2 else net)
            for ip in hosts:
                s = str(ip)
                if s not in seen:
                    seen.add(s)
                    out.append((s, None))
            continue
        except ValueError:
            pass
        ip = resolve_host(spec)
        if ip is None:
            print(f"[!] could not resolve {spec}", file=sys.stderr)
            continue
        if ip not in seen:
            seen.add(ip)
            out.append((ip, spec))
    return out


def parse_ports(spec: str) -> list[int]:
    if spec in ("", "default", "common"):
        return DEFAULT_PORTS
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


# --------------------------------------------------------------------------- #
# Exporters                                                                   #
# --------------------------------------------------------------------------- #

def export_json(results, meta) -> str:
    return json.dumps({"meta": meta, "hosts": results}, indent=2)


def export_csv(results) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["host", "hostname", "os_guess", "ttl", "port", "protocol",
                     "state", "service", "version", "banner", "vuln_hints"])
    for h in results:
        for p in h["ports"]:
            writer.writerow([
                h["host"], h.get("hostname") or "", h.get("os_guess") or "",
                h.get("ttl") if h.get("ttl") is not None else "",
                p["port"], p["protocol"], p["state"], p["service"],
                p.get("version") or "",
                (p.get("banner") or "").replace("\n", " ").replace("\r", " "),
                " ; ".join(p.get("vuln_hints", [])),
            ])
    return buf.getvalue()


def export_xml(results, meta) -> str:
    root = ET.Element("scanresult")
    m = ET.SubElement(root, "meta")
    for k, v in meta.items():
        ET.SubElement(m, k).text = str(v)
    for h in results:
        hattr = {"addr": h["host"]}
        if h.get("hostname"):
            hattr["hostname"] = h["hostname"]
        if h.get("os_guess"):
            hattr["os"] = h["os_guess"]
        if h.get("ttl") is not None:
            hattr["ttl"] = str(h["ttl"])
        he = ET.SubElement(root, "host", hattr)
        ports_el = ET.SubElement(he, "ports")
        for p in h["ports"]:
            pe = ET.SubElement(ports_el, "port", {
                "portid": str(p["port"]), "protocol": p["protocol"]})
            ET.SubElement(pe, "state", {"state": p["state"]})
            sattr = {"name": p["service"]}
            if p.get("version"):
                sattr["version"] = p["version"]
            ET.SubElement(pe, "service", sattr)
            if p.get("banner"):
                ET.SubElement(pe, "banner").text = p["banner"]
            for hint in p.get("vuln_hints", []):
                ET.SubElement(pe, "vuln").text = hint
    rough = ET.tostring(root, encoding="unicode")
    return minidom.parseString(rough).toprettyxml(indent="  ")


HTML_CSS = """
:root{--bg:#0f1117;--card:#171a23;--line:#262a36;--fg:#e6e8ee;--mut:#8a93a6;
--ok:#3fb950;--warn:#d29922;--bad:#f85149;--accent:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1100px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 24px}
.host{background:var(--card);border:1px solid var(--line);border-radius:10px;
margin:0 0 20px;overflow:hidden}
.host>summary{cursor:pointer;list-style:none;padding:14px 18px;display:flex;
gap:14px;align-items:baseline;flex-wrap:wrap}
.host>summary::-webkit-details-marker{display:none}
.ip{font-size:16px;font-weight:600;color:var(--accent)}
.tag{font-size:12px;color:var(--mut)}
.osbadge{margin-left:auto;font-size:12px;background:#1f2430;border:1px solid
var(--line);padding:2px 10px;border-radius:20px;color:var(--fg)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 18px;border-top:1px solid var(--line);
vertical-align:top}
th{color:var(--mut);font-weight:500;background:#12151d}
.port{color:var(--accent);font-weight:600}
.svc{color:var(--fg)}.banner{color:var(--mut);word-break:break-word;max-width:520px}
.hint{color:var(--warn);font-size:12px;display:block;margin-top:4px}
.state-open{color:var(--ok)}.state-filtered{color:var(--warn)}
.state-closed{color:var(--bad)}
footer{color:var(--mut);font-size:12px;text-align:center;margin-top:28px}
"""


def export_html(results, meta) -> str:
    parts = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             "<title>mpscan report</title><style>", HTML_CSS, "</style></head><body>",
             "<div class='wrap'>",
             "<h1>Multi-Protocol Scan Report</h1>",
             f"<p class='sub'>Generated {escape(meta.get('finished',''))} &middot; "
             f"{len(results)} host(s) &middot; "
             f"{sum(len(h['ports']) for h in results)} open port(s)</p>"]

    for h in results:
        open_ports = [p for p in h["ports"] if p["state"] == "open"]
        parts.append("<details class='host' open>")
        tags = []
        if h.get("hostname"):
            tags.append(f"<span class='tag'>{escape(h['hostname'])}</span>")
        if h.get("input"):
            tags.append(f"<span class='tag'>(input: {escape(h['input'])})</span>")
        if h.get("ttl") is not None:
            tags.append(f"<span class='tag'>TTL {h['ttl']}</span>")
        parts.append(
            f"<summary><span class='ip'>{escape(h['host'])}</span>"
            + "".join(tags)
            + f"<span class='osbadge'>{escape(h.get('os_guess') or 'unknown')}</span>"
            "</summary>")
        if not h["ports"]:
            parts.append("<table><tr><td class='tag'>No open ports found.</td>"
                         "</tr></table></details>")
            continue
        parts.append("<table><thead><tr><th>Port</th><th>Service</th>"
                     "<th>Version</th><th>Banner / Findings</th></tr></thead><tbody>")
        for p in h["ports"]:
            hints = "".join(f"<span class='hint'>&#9888; {escape(x)}</span>"
                            for x in p.get("vuln_hints", []))
            parts.append(
                f"<tr><td class='port'>{p['port']}/{p['protocol']} "
                f"<span class='state-{p['state']}'>&#9679;</span></td>"
                f"<td class='svc'>{escape(p['service'])}</td>"
                f"<td>{escape(p.get('version') or '')}</td>"
                f"<td class='banner'>{escape(p.get('banner') or '')}{hints}</td></tr>")
        parts.append("</tbody></table></details>")

    parts.append("<footer>mpscan &middot; standard-library only &middot; "
                 "use only on authorized targets.</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)


def write_output(text: str, path: str, label: str):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"[+] {label} written to {path}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Console summary                                                             #
# --------------------------------------------------------------------------- #

def print_summary(results):
    for h in results:
        header = f"\n=== {h['host']}"
        if h.get("hostname"):
            header += f" ({h['hostname']})"
        header += f"  [OS guess: {h.get('os_guess')}"
        if h.get("ttl") is not None:
            header += f", TTL {h['ttl']}"
        header += "] ==="
        print(header)
        if not h["ports"]:
            print("  (no open ports)")
            continue
        for p in h["ports"]:
            line = f"  {p['port']:>5}/{p['protocol']}  {p['state']:<9} {p['service']}"
            if p.get("version"):
                line += f"  [{p['version']}]"
            print(line)
            if p.get("banner"):
                snippet = p["banner"].replace("\n", " ")[:140]
                print(f"        {snippet}")
            for hint in p.get("vuln_hints", []):
                print(f"        ! {hint}")


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mpscan",
        description="Enhanced multi-protocol scanner (standard library only).",
        epilog="Only scan systems you own or are authorized to test.")
    p.add_argument("targets", nargs="+",
                   help="hosts, IPs, or CIDR ranges (e.g. 10.0.0.0/24 host.example)")
    p.add_argument("-p", "--ports", default="default",
                   help="ports: 'default', 'all', '1-1024', or '22,80,443'")
    p.add_argument("-t", "--threads", type=int, default=50,
                   help="concurrent connections per host (default 50)")
    p.add_argument("--timeout", type=float, default=3.0,
                   help="per-connection timeout in seconds (default 3)")
    # Stealth
    p.add_argument("--rate", type=float, default=0.0,
                   help="max connections/sec globally (0 = unlimited)")
    p.add_argument("--jitter", type=float, default=0.0,
                   help="random extra delay 0..N sec per connection")
    # Proxy
    p.add_argument("--proxy", default=None,
                   help="scheme://[user:pass@]host:port (socks5|socks4|http)")
    # Toggles
    p.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    p.add_argument("--no-os", action="store_true", help="skip TTL OS fingerprinting")
    p.add_argument("--no-dns", action="store_true", help="skip reverse DNS")
    p.add_argument("--show-closed", action="store_true",
                   help="include closed/filtered ports in results")
    # Output
    p.add_argument("--json", metavar="FILE", help="write JSON output")
    p.add_argument("--csv", metavar="FILE", help="write CSV output")
    p.add_argument("--xml", metavar="FILE", help="write nmap-like XML output")
    p.add_argument("--html", metavar="FILE", help="write HTML report")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress the console summary")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        proxy = ProxyConfig.parse(args.proxy)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if proxy and not args.no_os:
        # ICMP/ping cannot traverse a TCP CONNECT proxy.
        print("[i] proxy set: disabling TTL OS fingerprinting (ICMP can't be proxied)",
              file=sys.stderr)
        args.no_os = True

    ports = parse_ports(args.ports)
    targets = expand_targets(args.targets)
    if not targets:
        print("[!] no resolvable targets.", file=sys.stderr)
        return 1

    limiter = RateLimiter(rate=args.rate, jitter=args.jitter)

    started = datetime.now(timezone.utc)
    print(f"[i] scanning {len(targets)} host(s) x {len(ports)} port(s)"
          f"{' via ' + args.proxy if proxy else ''}", file=sys.stderr)
    print("[i] authorized use only.", file=sys.stderr)

    results = []
    for ip, origin in targets:
        results.append(scan_host(ip, origin, ports, args, limiter, proxy))

    finished = datetime.now(timezone.utc)
    meta = {
        "tool": "mpscan",
        "started": started.isoformat(timespec="seconds"),
        "finished": finished.isoformat(timespec="seconds"),
        "duration_sec": round((finished - started).total_seconds(), 2),
        "hosts_scanned": len(targets),
        "ports_per_host": len(ports),
        "proxy": args.proxy or None,
    }

    if not args.quiet:
        print_summary(results)

    if args.json:
        write_output(export_json(results, meta), args.json, "JSON")
    if args.csv:
        write_output(export_csv(results), args.csv, "CSV")
    if args.xml:
        write_output(export_xml(results, meta), args.xml, "XML")
    if args.html:
        write_output(export_html(results, meta), args.html, "HTML report")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted.", file=sys.stderr)
        sys.exit(130)
