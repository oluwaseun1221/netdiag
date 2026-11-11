#!/usr/bin/env python3
"""
netdiag - first-line network troubleshooting for staff computers (INTECU).

Runs layered checks (local address -> gateway -> DNS -> destination -> quality),
prints a plain-English verdict for staff and saves a technical report
(text + JSON) for IT.

Requires Python 3.11+ and nothing else (standard library only).

    python netdiag.py                  # staff view
    python netdiag.py -v               # IT view: details + raw command output
    python netdiag.py --init-config    # write a sample netdiag.toml
    python netdiag.py --selftest       # verify the parsers (works on any OS)

Exit codes: 0 healthy, 1 warnings, 2 failure, 3 internal error.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import http.client
import json
import os
import platform
import re
import secrets
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import tomllib
import urllib.request
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

__version__ = "1.0.0"
IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Config:
    destination_host: str = "example.com"   # something staff are always allowed to reach
    destination_port: int = 443
    dns_test_hostname: str = ""             # blank = use destination_host
    public_resolvers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    ping_count: int = 10
    gateway_ping_count: int = 4
    loss_warn_pct: float = 5.0
    loss_fail_pct: float = 50.0
    latency_warn_ms: float = 150.0
    gateway_latency_warn_ms: float = 30.0
    tcp_timeout: float = 4.0
    dns_timeout: float = 3.0
    http_probe: bool = True
    trace_on_failure: bool = True
    trace_max_hops: int = 15
    report_dir: str = "reports"


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


def load_config(path: Path | None) -> tuple[Config, str]:
    cfg = Config()
    candidates = [path] if path else [app_dir() / "netdiag.toml", Path.cwd() / "netdiag.toml"]
    for p in candidates:
        if p is None or not p.is_file():
            continue
        data = tomllib.loads(p.read_text(encoding="utf-8"))
        known = {f.name for f in fields(Config)}
        for key, value in data.items():
            if key not in known:
                print(f"warning: unknown setting '{key}' in {p}", file=sys.stderr)
                continue
            current = getattr(cfg, key)
            if isinstance(current, bool):
                value = bool(value)
            elif isinstance(current, int):
                value = int(value)
            elif isinstance(current, float):
                value = float(value)
            setattr(cfg, key, value)
        return cfg, str(p)
    if path:
        raise FileNotFoundError(f"config file not found: {path}")
    return cfg, "built-in defaults"


def sample_config() -> str:
    d = Config()
    return textwrap.dedent(f"""\
        # netdiag.toml - settings for netdiag.py (all optional)

        # An address staff are always allowed to reach (use your approved destination).
        destination_host = "{d.destination_host}"
        destination_port = {d.destination_port}
        dns_test_hostname = ""            # blank = same as destination_host

        # Public resolvers used only to tell "our DNS is broken" from "no internet".
        public_resolvers = {json.dumps(d.public_resolvers)}

        ping_count = {d.ping_count}
        gateway_ping_count = {d.gateway_ping_count}
        loss_warn_pct = {d.loss_warn_pct}
        loss_fail_pct = {d.loss_fail_pct}
        latency_warn_ms = {d.latency_warn_ms}
        gateway_latency_warn_ms = {d.gateway_latency_warn_ms}
        tcp_timeout = {d.tcp_timeout}
        dns_timeout = {d.dns_timeout}
        http_probe = true
        trace_on_failure = true
        trace_max_hops = {d.trace_max_hops}
        report_dir = "{d.report_dir}"
        """)


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class Status(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"
    SKIP = "skip"


@dataclass(slots=True)
class CheckResult:
    id: str
    title: str
    status: Status
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    duration_ms: float = 0.0


@dataclass(slots=True)
class Diagnosis:
    verdict: str
    severity: Status
    explanation: str
    next_action: str
    technical: str = ""


@dataclass(slots=True)
class CmdResult:
    code: int
    output: str


@dataclass(slots=True)
class Probe:
    ok: bool
    ms: float
    error: str = ""


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 1)


# --------------------------------------------------------------------------- #
# Running commands
# --------------------------------------------------------------------------- #
def run_cmd(args: list[str], timeout: float = 15.0) -> CmdResult:
    """Run a command (argument list, never a shell). Never raises."""
    kwargs: dict[str, Any] = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        p = subprocess.run(args, capture_output=True, text=True, errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL, **kwargs)
        return CmdResult(p.returncode, (p.stdout or "") + (p.stderr or ""))
    except subprocess.TimeoutExpired as e:
        partial = e.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        return CmdResult(-1, f"{partial}\n[timed out after {timeout:.0f}s: {' '.join(args)}]")
    except FileNotFoundError:
        return CmdResult(-2, f"[command not found: {args[0]}]")
    except OSError as e:
        return CmdResult(-3, f"[could not run {args[0]}: {e}]")


# --------------------------------------------------------------------------- #
# Parsers (pure functions - covered by --selftest)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Route:
    gateway: str
    interface_ip: str
    metric: int
    iface: str = ""


@dataclass(slots=True)
class Adapter:
    name: str
    ipv4: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Hop:
    n: int
    ip: str | None


@dataclass(slots=True)
class PingStats:
    sent: int
    received: int
    times: list[float]

    @property
    def loss_pct(self) -> float:
        return round(100 * (self.sent - self.received) / self.sent, 1) if self.sent else 100.0

    @property
    def min(self) -> float | None:
        return min(self.times) if self.times else None

    @property
    def avg(self) -> float | None:
        return round(statistics.fmean(self.times), 1) if self.times else None

    @property
    def max(self) -> float | None:
        return max(self.times) if self.times else None

    @property
    def jitter(self) -> float | None:
        return round(statistics.pstdev(self.times), 1) if len(self.times) > 1 else None


def parse_routes_windows(text: str) -> list[Route]:
    """`route print -4 0.0.0.0` - locale-proof, only numbers matter."""
    routes = [
        Route(m[1], m[2], int(m[3]))
        for m in re.finditer(rf"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+({IPV4})\s+({IPV4})\s+(\d+)", text, re.M)
    ]
    return sorted(routes, key=lambda r: r.metric)


def parse_routes_linux(text: str) -> list[Route]:
    routes = []
    for line in text.splitlines():
        m = re.match(rf"\s*default via ({IPV4}) dev (\S+)", line)
        if m:
            metric = re.search(r"metric (\d+)", line)
            routes.append(Route(m[1], "", int(metric[1]) if metric else 0, m[2]))
    return sorted(routes, key=lambda r: r.metric)


def parse_route_macos(text: str) -> list[Route]:
    gw = re.search(rf"gateway:\s*({IPV4})", text)
    ifc = re.search(r"interface:\s*(\S+)", text)
    return [Route(gw[1], "", 0, ifc[1] if ifc else "")] if gw else []


def parse_ipconfig(text: str) -> list[Adapter]:
    """Parse `ipconfig /all`. Labels are localised, so only 'ipv4' / 'dns' keywords are used."""
    adapters: list[Adapter] = []
    cur: Adapter | None = None
    collecting_dns = False
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[:1] not in " \t" and line.rstrip().endswith(":"):
            cur = Adapter(line.strip().rstrip(":"))
            adapters.append(cur)
            collecting_dns = False
            continue
        if cur is None:
            continue
        if re.search(r"\s:(?:\s|$)", line):          # "label . . . : value"
            label, _, value = line.partition(" :")
            ips = re.findall(IPV4, value)
            label = label.lower()
            collecting_dns = False
            if "dns" in label:
                cur.dns.extend(ips)
                collecting_dns = True
            elif "ipv4" in label:
                cur.ipv4.extend(ips)
        elif collecting_dns and re.fullmatch(IPV4, line.strip()):
            cur.dns.append(line.strip())
    return adapters


def parse_ping(text: str, sent: int) -> PingStats:
    """Count real replies by their 'TTL=' field (not localised) and read 'time=Xms'."""
    times: list[float] = []
    received = 0
    for line in text.splitlines():
        if re.search(r"(?i)\bttl[=:]\s*\d+", line):
            received += 1
            m = re.search(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", line)
            if m:
                times.append(float(m[1].replace(",", ".")))
    return PingStats(sent, min(received, sent), times)


def parse_trace(text: str) -> list[Hop]:
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d{1,2})\s+(.*)$", line)
        if m:
            ips = re.findall(IPV4, m[2])
            hops.append(Hop(int(m[1]), ips[0] if ips else None))
    return hops


# --------------------------------------------------------------------------- #
# DNS over raw UDP (lets us test each DNS server separately, in any language)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class DnsReply:
    responded: bool
    ips: list[str]
    ms: float
    error: str = ""


def build_dns_query(name: str) -> tuple[int, bytes]:
    qid = secrets.randbelow(65536)
    labels = name.rstrip(".").encode("idna").split(b".")
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return qid, struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def _skip_name(data: bytes, pos: int) -> int:
    while True:
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += length + 1


def parse_dns_response(data: bytes, qid: int) -> tuple[int, list[str]]:
    if len(data) < 12:
        raise ValueError("reply too short")
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != qid:
        raise ValueError("reply id mismatch")
    pos = 12
    for _ in range(qd):
        pos = _skip_name(data, pos) + 4
    ips: list[str] = []
    for _ in range(an):
        pos = _skip_name(data, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(data[pos:pos + 4]))
        pos += rdlen
    return flags & 0xF, ips


RCODES = {1: "format error", 2: "server failure", 3: "name does not exist", 5: "refused"}


def dns_query(server: str, name: str, timeout: float) -> DnsReply:
    t0 = time.perf_counter()
    try:
        qid, packet = build_dns_query(name)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (server, 53))
            data, _ = s.recvfrom(4096)
        rcode, ips = parse_dns_response(data, qid)
    except TimeoutError:
        return DnsReply(False, [], _ms(t0), "no answer (timed out)")
    except (OSError, ValueError, IndexError, struct.error, UnicodeError) as e:
        return DnsReply(False, [], _ms(t0), str(e))
    error = "" if ips else RCODES.get(rcode, f"no address returned (rcode {rcode})")
    return DnsReply(True, ips, _ms(t0), error)


def resolve_system(host: str) -> list[str]:
    """What applications really use (OS resolver, hosts file, DNS suffixes...)."""
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    return sorted({i[4][0] for i in infos})


# --------------------------------------------------------------------------- #
# Network state (collected once, analysed by the checks)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class NetState:
    local_ip: str | None = None
    gateway: str | None = None
    adapter: str = ""
    dns_servers: list[str] = field(default_factory=list)
    apipa: list[str] = field(default_factory=list)
    route_count: int = 0
    raw: str = ""


def _udp_local_ip() -> str | None:
    """Ask the OS which address it would use to reach the internet (sends nothing)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("203.0.113.1", 9))
            return s.getsockname()[0]
    except OSError:
        return None


def _resolv_conf() -> list[str]:
    try:
        text = Path("/etc/resolv.conf").read_text(errors="replace")
    except OSError:
        return []
    return re.findall(rf"^\s*nameserver\s+({IPV4})", text, re.M)


def collect_state() -> NetState:
    st = NetState()
    raw: list[str] = []
    routes: list[Route] = []
    adapters: list[Adapter] = []

    if IS_WINDOWS:
        ipc = run_cmd(["ipconfig", "/all"])
        rt = run_cmd(["route", "print", "-4", "0.0.0.0"])
        raw += [f"$ ipconfig /all\n{ipc.output}", f"$ route print -4 0.0.0.0\n{rt.output}"]
        adapters = parse_ipconfig(ipc.output)
        routes = parse_routes_windows(rt.output)
        if routes:
            st.local_ip = routes[0].interface_ip
    elif IS_MAC:
        rt = run_cmd(["route", "-n", "get", "default"])
        raw.append(f"$ route -n get default\n{rt.output}")
        routes = parse_route_macos(rt.output)
        if routes and routes[0].iface:
            ip = run_cmd(["ipconfig", "getifaddr", routes[0].iface]).output.strip()
            if re.fullmatch(IPV4, ip):
                st.local_ip = ip
            st.adapter = routes[0].iface
        st.dns_servers = _resolv_conf()
    else:
        rt = run_cmd(["ip", "-4", "route", "show", "default"])
        raw.append(f"$ ip -4 route show default\n{rt.output}")
        routes = parse_routes_linux(rt.output)
        if routes:
            addr = run_cmd(["ip", "-4", "-o", "addr", "show", "dev", routes[0].iface])
            raw.append(f"$ ip -4 -o addr show dev {routes[0].iface}\n{addr.output}")
            m = re.search(rf"inet ({IPV4})/", addr.output)
            if m:
                st.local_ip = m[1]
            st.adapter = routes[0].iface
        st.dns_servers = _resolv_conf()

    st.route_count = len(routes)
    if routes:
        st.gateway = routes[0].gateway
    if not st.local_ip and routes:
        st.local_ip = _udp_local_ip()

    if adapters:
        st.apipa = [ip for a in adapters for ip in a.ipv4 if ip.startswith("169.254.")]
        mine = next((a for a in adapters if st.local_ip and st.local_ip in a.ipv4), None)
        if mine:
            st.adapter, st.dns_servers = mine.name, list(dict.fromkeys(mine.dns))
        elif not st.dns_servers:
            st.dns_servers = list(dict.fromkeys(ip for a in adapters for ip in a.dns))
    st.raw = "\n\n".join(raw)
    return st


# --------------------------------------------------------------------------- #
# Async probes
# --------------------------------------------------------------------------- #
async def tcp_probe(host: str, port: int, timeout: float) -> Probe:
    t0 = time.perf_counter()
    try:
        async with asyncio.timeout(timeout):
            _reader, writer = await asyncio.open_connection(host, port)
        ms = _ms(t0)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return Probe(True, ms)
    except TimeoutError:
        return Probe(False, _ms(t0), "timed out")
    except OSError as e:
        return Probe(False, _ms(t0), e.strerror or str(e))


async def ping_host(host: str, count: int, wait_s: int = 1) -> tuple[PingStats, str]:
    if IS_WINDOWS:
        args = ["ping", "-n", str(count), "-w", str(wait_s * 1000), host]
    elif IS_MAC:
        args = ["ping", "-c", str(count), "-W", str(wait_s * 1000), host]
    else:
        args = ["ping", "-c", str(count), "-W", str(wait_s), host]
    res = await asyncio.to_thread(run_cmd, args, count * (wait_s + 1) + 10)
    return parse_ping(res.output, count), res.output


def http_probe_sync(host: str, port: int, timeout: float) -> dict[str, Any]:
    if port == 443:
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=ssl.create_default_context())
    elif port == 80:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    else:
        return {"skipped": True}
    t0 = time.perf_counter()
    try:
        conn.request("HEAD", "/", headers={"User-Agent": f"netdiag/{__version__}",
                                           "Connection": "close"})
        resp = conn.getresponse()
        return {"status": resp.status, "location": resp.getheader("Location") or "", "ms": _ms(t0)}
    except ssl.SSLCertVerificationError as e:
        return {"error": f"certificate not trusted ({e.verify_message})", "cert": True}
    except (OSError, http.client.HTTPException) as e:
        return {"error": str(e) or type(e).__name__}
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def make(cid: str, title: str, status: Status, summary: str, t0: float | None = None,
         details: dict[str, Any] | None = None, raw: str = "") -> CheckResult:
    return CheckResult(cid, title, status, summary, details or {}, raw,
                       _ms(t0) if t0 is not None else 0.0)


def skipped(cid: str, title: str, reason: str) -> CheckResult:
    return make(cid, title, Status.SKIP, reason)


def check_system() -> CheckResult:
    t0 = time.perf_counter()
    proxies = urllib.request.getproxies()
    details = {
        "hostname": socket.gethostname(),
        "user": getpass.getuser(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "proxy_settings": proxies or "none",
    }
    return make("system", "System", Status.INFO,
                f"{details['hostname']} - {platform.system()} {platform.release()}", t0, details)


def check_local_ip(st: NetState) -> CheckResult:
    t0 = time.perf_counter()
    details = {"ip": st.local_ip, "adapter": st.adapter, "apipa_addresses": st.apipa}
    if st.local_ip and st.local_ip.startswith("169.254."):
        details["apipa"] = True
        return make("local_ip", "Local IP address", Status.FAIL,
                    f"{st.local_ip} is a self-assigned address - the network did not give this PC an address (DHCP failed)",
                    t0, details, st.raw)
    if not st.local_ip:
        if st.apipa:
            details["apipa"] = True
            return make("local_ip", "Local IP address", Status.FAIL,
                        f"Only a self-assigned address ({st.apipa[0]}) - DHCP failed", t0, details, st.raw)
        return make("local_ip", "Local IP address", Status.FAIL,
                    "No active network connection (no IPv4 address)", t0, details, st.raw)
    where = f" on {st.adapter}" if st.adapter else ""
    return make("local_ip", "Local IP address", Status.PASS, f"{st.local_ip}{where}", t0, details)


def check_gateway_config(st: NetState) -> CheckResult:
    t0 = time.perf_counter()
    details = {"gateway": st.gateway, "default_routes": st.route_count}
    if not st.gateway:
        return make("gateway", "Default gateway", Status.FAIL,
                    "No default gateway configured - this PC has no route to other networks", t0, details)
    return make("gateway", "Default gateway", Status.PASS, st.gateway, t0, details)


def check_wifi() -> CheckResult | None:
    if not IS_WINDOWS:
        return None
    t0 = time.perf_counter()
    res = run_cmd(["netsh", "wlan", "show", "interfaces"])
    ssid = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", res.output, re.M)
    if not ssid:
        return make("wifi", "Wi-Fi signal", Status.SKIP, "Not connected over Wi-Fi", t0, raw=res.output)
    sig = re.search(r"(\d{1,3})\s*%", res.output)
    signal = int(sig[1]) if sig else None
    details = {"ssid": ssid[1], "signal_pct": signal}
    if signal is not None and signal < 40:
        return make("wifi", "Wi-Fi signal", Status.WARN,
                    f"Weak signal ({signal}%) on '{ssid[1]}'", t0, details, res.output)
    text = f"'{ssid[1]}'" + (f", signal {signal}%" if signal is not None else "")
    return make("wifi", "Wi-Fi signal", Status.PASS, text, t0, details, res.output)


async def check_gateway_ping(cfg: Config, st: NetState) -> CheckResult:
    t0 = time.perf_counter()
    stats, raw = await ping_host(st.gateway or "", cfg.gateway_ping_count)
    details = {"loss_pct": stats.loss_pct, "avg_ms": stats.avg, "max_ms": stats.max}
    if stats.received == 0:
        return make("gateway_ping", "Gateway reachable", Status.FAIL,
                    f"No reply from {st.gateway} (0 of {stats.sent} pings)", t0, details, raw)
    note = f"{stats.received}/{stats.sent} replies, avg {stats.avg} ms"
    if stats.loss_pct > 0 or (stats.avg or 0) > cfg.gateway_latency_warn_ms:
        return make("gateway_ping", "Gateway reachable", Status.WARN,
                    f"{note} - local link is unstable or slow", t0, details, raw)
    return make("gateway_ping", "Gateway reachable", Status.PASS, note, t0, details, raw)


async def check_dns(cfg: Config, st: NetState) -> CheckResult:
    t0 = time.perf_counter()
    host = cfg.dns_test_hostname or cfg.destination_host

    async def system() -> tuple[list[str], str]:
        try:
            async with asyncio.timeout(cfg.dns_timeout + 2):
                return await asyncio.to_thread(resolve_system, host), ""
        except TimeoutError:
            return [], "timed out"
        except OSError as e:
            return [], e.strerror or str(e)

    async def query(server: str) -> DnsReply:
        return await asyncio.to_thread(dns_query, server, host, cfg.dns_timeout)

    configured = st.dns_servers[:4]
    (sys_ips, sys_err), cfg_replies, pub_replies = await asyncio.gather(
        system(),
        asyncio.gather(*(query(s) for s in configured)),
        asyncio.gather(*(query(s) for s in cfg.public_resolvers)),
    )
    details: dict[str, Any] = {
        "host": host,
        "system_ok": bool(sys_ips), "system_ips": sys_ips, "system_error": sys_err,
        "configured": {s: r.responded for s, r in zip(configured, cfg_replies)},
        "configured_detail": {s: asdict(r) for s, r in zip(configured, cfg_replies)},
        "public": {s: bool(r.ips) for s, r in zip(cfg.public_resolvers, pub_replies)},
        "public_detail": {s: asdict(r) for s, r in zip(cfg.public_resolvers, pub_replies)},
        "public_ok": any(r.ips for r in pub_replies),
    }
    silent = [s for s, r in zip(configured, cfg_replies) if not r.responded]
    if sys_ips:
        if silent:
            return make("dns", "DNS resolution", Status.WARN,
                        f"{host} resolves, but DNS server {', '.join(silent)} did not answer", t0, details)
        return make("dns", "DNS resolution", Status.PASS, f"{host} -> {', '.join(sys_ips[:3])}", t0, details)
    reason = sys_err or "no address returned"
    if details["public_ok"]:
        extra = "public DNS answers, so the problem is with this network's DNS"
    else:
        extra = "public DNS did not answer either"
    return make("dns", "DNS resolution", Status.FAIL,
                f"Cannot resolve {host} ({reason}); {extra}", t0, details)


async def check_destination(cfg: Config) -> CheckResult:
    t0 = time.perf_counter()
    host, port = cfg.destination_host, cfg.destination_port
    main, *ip_probes = await asyncio.gather(
        tcp_probe(host, port, cfg.tcp_timeout),
        *(tcp_probe(ip, 443, cfg.tcp_timeout) for ip in cfg.public_resolvers),
    )
    details = {
        "host": host, "port": port, "host_ok": main.ok, "host_error": main.error, "connect_ms": main.ms,
        "ip_probes": {ip: p.ok for ip, p in zip(cfg.public_resolvers, ip_probes)},
        "ip_probe_ok": any(p.ok for p in ip_probes),
    }
    if main.ok:
        return make("destination", "Approved destination", Status.PASS,
                    f"Connected to {host}:{port} in {main.ms} ms", t0, details)
    return make("destination", "Approved destination", Status.FAIL,
                f"Cannot connect to {host}:{port} ({main.error})", t0, details)


async def check_http(cfg: Config) -> CheckResult:
    t0 = time.perf_counter()
    host, port = cfg.destination_host, cfg.destination_port
    out = await asyncio.to_thread(http_probe_sync, host, port, cfg.tcp_timeout + 2)
    title = "Web response"
    if out.get("skipped"):
        return make("http", title, Status.SKIP, "Only checked for ports 80 and 443", t0)
    if "error" in out:
        hint = (" - a sign-in page, proxy or web filter may be intercepting traffic"
                if out.get("cert") else "")
        return make("http", title, Status.WARN, f"Connected, but the web request failed: {out['error']}{hint}",
                    t0, out)
    status, location = out["status"], out["location"]
    strip = lambda h: (h or "").lower().removeprefix("www.")  # noqa: E731
    target = urlparse(location).hostname
    if status == 511 or (300 <= status < 400 and target and strip(target) != strip(host)):
        return make("http", title, Status.WARN,
                    f"HTTP {status}, redirected to {target or 'another site'} - the network may require a sign-in",
                    t0, out)
    return make("http", title, Status.PASS, f"HTTP {status} in {out['ms']} ms", t0, out)


async def check_quality(cfg: Config) -> CheckResult:
    t0 = time.perf_counter()
    host = cfg.destination_host
    stats, raw = await ping_host(host, cfg.ping_count)
    if stats.received == 0:   # ICMP may be blocked: time TCP connects instead
        probes = [await tcp_probe(host, cfg.destination_port, cfg.tcp_timeout) for _ in range(5)]
        times = [p.ms for p in probes if p.ok]
        details = {"method": "tcp", "samples": len(probes), "failed": len(probes) - len(times)}
        if not times:
            return make("quality", "Speed and stability", Status.FAIL,
                        "No replies to ping or TCP connections", t0, details, raw)
        avg = round(statistics.fmean(times), 1)
        details["avg_ms"] = avg
        status = Status.WARN if avg >= cfg.latency_warn_ms or details["failed"] else Status.PASS
        return make("quality", "Speed and stability", status,
                    f"Ping is blocked; TCP connect time avg {avg} ms ({details['failed']} of 5 failed)",
                    t0, details, raw)
    details = {"method": "icmp", "loss_pct": stats.loss_pct, "min_ms": stats.min, "avg_ms": stats.avg,
               "max_ms": stats.max, "jitter_ms": stats.jitter}
    text = f"loss {stats.loss_pct}%, avg {stats.avg} ms (min {stats.min}, max {stats.max}, jitter {stats.jitter})"
    if stats.loss_pct >= cfg.loss_fail_pct:
        status = Status.FAIL
    elif stats.loss_pct >= cfg.loss_warn_pct or (stats.avg or 0) >= cfg.latency_warn_ms:
        status = Status.WARN
    else:
        status = Status.PASS
    return make("quality", "Speed and stability", status, text, t0, details, raw)


async def check_route(cfg: Config, target: str) -> CheckResult:
    t0 = time.perf_counter()
    n = cfg.trace_max_hops
    if IS_WINDOWS:
        args = ["tracert", "-d", "-h", str(n), "-w", "800", target]
    else:
        args = ["traceroute", "-n", "-m", str(n), "-w", "1", target]
    res = await asyncio.to_thread(run_cmd, args, n * 3 + 20)
    if res.code == -2:
        return make("route", "Route to destination", Status.SKIP, "Trace tool not available", t0, raw=res.output)
    hops = parse_trace(res.output)
    answered = [h for h in hops if h.ip]
    details = {"target": target, "hops": [asdict(h) for h in hops],
               "last_responding_hop": asdict(answered[-1]) if answered else None}
    if not answered:
        return make("route", "Route to destination", Status.INFO,
                    f"No hop answered on the way to {target}", t0, details, res.output)
    last = answered[-1]
    return make("route", "Route to destination", Status.INFO,
                f"Path stops answering after hop {last.n} ({last.ip}); {len(hops)} hops probed",
                t0, details, res.output)


# --------------------------------------------------------------------------- #
# Diagnosis (pure function: results in, verdict out)
# --------------------------------------------------------------------------- #
def diagnose(r: dict[str, CheckResult]) -> Diagnosis:
    F, W, P = Status.FAIL, Status.WARN, Status.PASS
    bad = [c for c in r.values() if c.status in (F, W)]
    technical = "; ".join(f"{c.title}: {c.summary}" for c in bad) or "All checks passed."

    def D(verdict: str, sev: Status, why: str, action: str) -> Diagnosis:
        return Diagnosis(verdict, sev, why, action, technical)

    ip, gw, gping = r.get("local_ip"), r.get("gateway"), r.get("gateway_ping")
    dns, dst = r.get("dns"), r.get("destination")
    wifi_weak = bool(r.get("wifi") and r["wifi"].status is W)

    if ip and ip.status is F:
        if ip.details.get("apipa"):
            return D("No network address (DHCP failure)", F,
                     "This computer is connected but the network never gave it an address, so it cannot talk to anything.",
                     "Reconnect the network cable or Wi-Fi, wait a minute and run this check again. If it still fails, "
                     "send the report to IT and mention a 169.254 address.")
        return D("Not connected to a network", F,
                 "This computer has no active network connection.",
                 "Check that the network cable is plugged in or that Wi-Fi is switched on and connected, then run this again.")
    if gw and gw.status is F:
        return D("No route out of this network", F,
                 "The computer has an address but no gateway, so it cannot reach other networks or the internet.",
                 "Disconnect and reconnect to the network, then run this again. If it persists, send the report to IT.")
    if dst is None:
        return D("Test incomplete", W, "The connection tests could not be completed.", "Run the check again.")

    d = dst.details
    internet_by_ip = bool(d.get("ip_probe_ok") or (dns and dns.details.get("public_ok")))

    if dst.status in (P, W):
        http = r.get("http")
        quality = r.get("quality")
        if http and http.status is W:
            return D("Connected, but web traffic is being intercepted", W,
                     "The connection works, but web requests are redirected or blocked - often a network sign-in page or web filter.",
                     "Open a web browser and look for a login page. Sign in with your network credentials, then retry. "
                     "If none appears, send the report to IT.")
        if quality and quality.status in (W, F):
            tip = " The Wi-Fi signal is weak, so move closer to an access point." if wifi_weak else ""
            return D("Connected, but slow or unstable", W,
                     "The network works but is losing packets or responding slowly, which causes freezing and failed uploads." + tip,
                     "Try a wired connection or move closer to an access point, then run again. If it stays slow, send the report to IT.")
        if wifi_weak:
            return D("Connected, but the Wi-Fi signal is weak", W,
                     "Everything responds, but the Wi-Fi signal is low and may drop out.",
                     "Move closer to an access point and run the check again.")
        return D("Everything looks healthy", P,
                 "The computer has an address, reaches the router, resolves names and connects to the approved destination.",
                 "If one website or app still fails, tell IT which one - the network itself is working.")

    # approved destination unreachable
    if gping and gping.status is F and not internet_by_ip:
        why = "The computer cannot reach the network's router, so the problem is on the local connection."
        if wifi_weak:
            why += " The Wi-Fi signal is also weak."
        return D("Cannot reach the network's router", F, why,
                 "Check the network cable or Wi-Fi connection, try another network port or move closer to an access "
                 "point, then run again. If it still fails, send the report to IT.")
    if dns and dns.status is F:
        configured = dns.details.get("configured", {})
        if internet_by_ip and configured and not any(configured.values()):
            return D("DNS server not responding", F,
                     "The internet works, but this network's DNS servers are not answering, so website names cannot be looked up.",
                     "Send the report to IT and tell them the DNS servers are not responding.")
        if internet_by_ip:
            return D("DNS problem", F,
                     "The internet is reachable, but website names are not being translated to addresses.",
                     "Send the report to IT and mention a DNS problem. Restarting the computer sometimes helps.")
        return D("No internet access beyond the router", F,
                 "The computer reaches its router, but nothing beyond it answers - not even name lookups.",
                 "This usually means a fault upstream of your building or a firewall block. Send the report to IT.")
    if internet_by_ip:
        return D("Approved destination unreachable", F,
                 "The internet works, but the approved destination does not answer - it may be down or blocked by a firewall.",
                 "Send the report to IT with the name of the destination you could not reach.")
    return D("No internet access beyond the router", F,
             "The computer reaches its router, but nothing beyond it answers.",
             "This usually means a fault upstream of your building or a firewall block. Send the report to IT.")


# --------------------------------------------------------------------------- #
# Console + reports
# --------------------------------------------------------------------------- #
LABEL = {Status.PASS: "[PASS]", Status.WARN: "[WARN]", Status.FAIL: "[FAIL]",
         Status.INFO: "[INFO]", Status.SKIP: "[SKIP]"}
COLOR = {Status.PASS: "32", Status.WARN: "33", Status.FAIL: "31", Status.INFO: "36", Status.SKIP: "90"}


def enable_ansi() -> bool:
    if not sys.stdout or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return False
    if IS_WINDOWS:
        try:
            import ctypes
            k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = k32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(k32.SetConsoleMode(handle, mode.value | 0x0004))
        except Exception:
            return False
    return os.environ.get("TERM") != "dumb"


class Console:
    def __init__(self, *, color: bool, quiet: bool, verbose: bool) -> None:
        self.color, self.quiet, self.verbose = color, quiet, verbose

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def out(self, text: str = "") -> None:
        if not self.quiet:
            print(text, flush=True)

    def header(self, host: str) -> None:
        bar = "-" * 72
        self.out(self.paint(f"\n netdiag {__version__} - network check for {host}", "1"))
        self.out(f" {datetime.now():%Y-%m-%d %H:%M:%S}\n {bar}")

    def note(self, text: str) -> None:
        self.out(self.paint(f"  ...{text}", "90"))

    def show(self, res: CheckResult) -> None:
        self.out(f" {self.paint(LABEL[res.status], COLOR[res.status])} {res.title:<22} {res.summary}")
        if self.verbose:
            for k, v in res.details.items():
                self.out(self.paint(f"          {k}: {v}", "90"))
            if res.raw.strip():
                for line in res.raw.rstrip().splitlines():
                    self.out(self.paint(f"          | {line}", "90"))

    def verdict(self, d: Diagnosis, files: list[str]) -> None:
        self.out(f" {'-' * 72}")
        self.out(f" RESULT: {self.paint(d.verdict, COLOR[d.severity] + ';1')}")
        for label, text in (("What it means", d.explanation), ("What to do", d.next_action)):
            body = textwrap.fill(text, 72, initial_indent=f" {label}: ", subsequent_indent="    ")
            self.out(body)
        for f in files:
            self.out(f" Report saved: {f}")
        self.out()


def render_text_report(results: dict[str, CheckResult], d: Diagnosis, cfg: Config,
                       cfg_source: str, when: datetime) -> str:
    sysinfo = results["system"].details if "system" in results else {}
    lines = [
        f"netdiag {__version__} report", "=" * 72,
        f"Generated : {when:%Y-%m-%d %H:%M:%S %Z}".rstrip(),
        f"Computer  : {sysinfo.get('hostname', '?')} (user {sysinfo.get('user', '?')})",
        f"System    : {sysinfo.get('os', '?')} / Python {sysinfo.get('python', '?')}",
        f"Config    : {cfg_source}",
        f"Target    : {cfg.destination_host}:{cfg.destination_port}", "",
        f"RESULT    : {d.verdict}  [{d.severity.upper()}]",
        f"Meaning   : {d.explanation}",
        f"Action    : {d.next_action}",
        f"Technical : {d.technical}", "", "CHECKS", "-" * 72,
    ]
    for res in results.values():
        lines.append(f"{LABEL[res.status]} {res.title}: {res.summary}  ({res.duration_ms} ms)")
        for k, v in res.details.items():
            lines.append(f"        {k}: {v}")
        if res.raw.strip():
            lines.append("        --- raw output ---")
            lines += [f"        {ln}" for ln in res.raw.rstrip().splitlines()]
        lines.append("")
    return "\n".join(lines)


def build_json(results: dict[str, CheckResult], d: Diagnosis, cfg: Config,
               cfg_source: str, when: datetime) -> dict[str, Any]:
    return {
        "tool": "netdiag", "version": __version__, "generated_at": when.isoformat(timespec="seconds"),
        "config_source": cfg_source, "config": asdict(cfg),
        "diagnosis": asdict(d),
        "checks": [asdict(r) for r in results.values()],
    }


def save_reports(text: str, data: dict[str, Any], cfg: Config, host: str, when: datetime) -> list[str]:
    base = Path(cfg.report_dir)
    if not base.is_absolute():
        base = app_dir() / base
    for folder in (base, Path(tempfile.gettempdir()) / "netdiag_reports"):
        try:
            folder.mkdir(parents=True, exist_ok=True)
            stem = f"{re.sub(r'[^A-Za-z0-9_.-]', '_', host)}_{when:%Y%m%d-%H%M%S}"
            (folder / f"{stem}.txt").write_text(text, encoding="utf-8")
            (folder / f"{stem}.json").write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            return [str(folder / f"{stem}.txt"), str(folder / f"{stem}.json")]
        except OSError:
            continue
    return []


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
async def run_diagnostics(cfg: Config, ui: Console, trace: bool = True) -> dict[str, CheckResult]:
    results: dict[str, CheckResult] = {}

    def add(res: CheckResult | None) -> CheckResult | None:
        if res is not None:
            results[res.id] = res
            ui.show(res)
        return res

    add(await asyncio.to_thread(check_system))
    state = await asyncio.to_thread(collect_state)
    ip = add(check_local_ip(state))
    gw = add(check_gateway_config(state))
    add(await asyncio.to_thread(check_wifi))

    assert ip and gw
    if ip.status is Status.FAIL or gw.status is Status.FAIL:
        for cid, title in (("gateway_ping", "Gateway reachable"), ("dns", "DNS resolution"),
                           ("destination", "Approved destination"), ("http", "Web response"),
                           ("quality", "Speed and stability")):
            add(skipped(cid, title, "Skipped - fix the local connection first"))
        return results

    ui.note("testing router, DNS and destination in parallel")
    gping, dns, dst = await asyncio.gather(
        check_gateway_ping(cfg, state), check_dns(cfg, state), check_destination(cfg))
    if gping.status is Status.FAIL and dst.status is Status.PASS:
        gping.status = Status.WARN
        gping.summary += " - but the internet works, so the router probably just ignores ping"
    for res in (gping, dns, dst):
        add(res)

    if dst.status is Status.PASS:
        ui.note(f"measuring speed and stability (about {cfg.ping_count} seconds)")
        http, quality = await asyncio.gather(
            check_http(cfg) if cfg.http_probe else asyncio.sleep(0, skipped("http", "Web response", "Disabled in settings")),
            check_quality(cfg))
        add(http)
        add(quality)
    else:
        add(skipped("http", "Web response", "Skipped - destination not reachable"))
        add(skipped("quality", "Speed and stability", "Skipped - destination not reachable"))
        if trace and cfg.trace_on_failure and gping.status is not Status.FAIL:
            ui.note("tracing the route (can take up to a minute)")
            target = cfg.destination_host if dns.status is not Status.FAIL else cfg.public_resolvers[0]
            add(await check_route(cfg, target))
    return results


def exit_code(d: Diagnosis) -> int:
    return {Status.PASS: 0, Status.WARN: 1}.get(d.severity, 2)


# --------------------------------------------------------------------------- #
# Self-test (no network needed)
# --------------------------------------------------------------------------- #
def selftest() -> int:
    n = 0

    def ok(cond: bool, label: str) -> None:
        nonlocal n
        n += 1
        if not cond:
            raise AssertionError(label)

    ipconfig = textwrap.dedent("""\
        Windows IP Configuration

           Host Name . . . . . . . . . . . . : PC-01

        Ethernet adapter Ethernet:

           Media State . . . . . . . . . . . : Media disconnected

        Wireless LAN adapter Wi-Fi:

           Connection-specific DNS Suffix  . : lan
           IPv4 Address. . . . . . . . . . . : 10.19.4.57(Preferred)
           Subnet Mask . . . . . . . . . . . : 255.255.0.0
           Default Gateway . . . . . . . . . : 10.19.0.1
           DNS Servers . . . . . . . . . . . : 10.19.0.2
                                               10.19.0.3
           NetBIOS over Tcpip. . . . . . . . : Enabled
        """)
    ad = parse_ipconfig(ipconfig)
    ok(len(ad) == 2 and ad[1].ipv4 == ["10.19.4.57"], "ipconfig ip")
    ok(ad[1].dns == ["10.19.0.2", "10.19.0.3"], "ipconfig dns")

    route = textwrap.dedent("""\
        Active Routes:
        Network Destination        Netmask          Gateway       Interface  Metric
                  0.0.0.0          0.0.0.0     192.168.56.1   192.168.56.10    291
                  0.0.0.0          0.0.0.0        10.19.0.1      10.19.4.57     45
        """)
    routes = parse_routes_windows(route)
    ok(routes[0].gateway == "10.19.0.1" and routes[0].interface_ip == "10.19.4.57", "route pick lowest metric")
    ok(parse_routes_linux("default via 192.168.1.1 dev wlan0 proto dhcp metric 600")[0].iface == "wlan0", "linux route")
    ok(parse_route_macos("   gateway: 192.168.0.1\n  interface: en0")[0].gateway == "192.168.0.1", "mac route")

    win_ping = ("Pinging 10.19.0.1 with 32 bytes of data:\n"
                "Reply from 10.19.0.1: bytes=32 time=2ms TTL=64\n"
                "Reply from 10.19.0.1: bytes=32 time<1ms TTL=64\n"
                "Request timed out.\n"
                "Reply from 10.19.4.57: Destination host unreachable.\n")
    s = parse_ping(win_ping, 4)
    ok(s.received == 2 and s.loss_pct == 50.0 and s.times == [2.0, 1.0], "windows ping")
    s = parse_ping("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms", 1)
    ok(s.received == 1 and s.avg == 12.3, "linux ping")

    hops = parse_trace("Tracing route to x [1.2.3.4]\nover a maximum of 15 hops:\n\n"
                       "  1    <1 ms    <1 ms    <1 ms  10.19.0.1\n"
                       "  2     *        *        *     Request timed out.\n")
    ok(len(hops) == 2 and hops[0].ip == "10.19.0.1" and hops[1].ip is None, "tracert")

    qid, packet = build_dns_query("example.com")
    reply = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + packet[12:] + b"\xc0\x0c" \
        + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
    ok(parse_dns_response(reply, qid) == (0, ["93.184.216.34"]), "dns wire format")

    def res(cid: str, status: Status, **details: Any) -> CheckResult:
        return CheckResult(cid, cid, status, cid, dict(details))

    good = {"local_ip": res("local_ip", Status.PASS), "gateway": res("gateway", Status.PASS),
            "gateway_ping": res("gateway_ping", Status.PASS),
            "dns": res("dns", Status.PASS, public_ok=True),
            "destination": res("destination", Status.PASS, ip_probe_ok=True),
            "quality": res("quality", Status.PASS)}
    ok(diagnose(good).severity is Status.PASS, "healthy")
    dns_bad = dict(good, dns=res("dns", Status.FAIL, public_ok=True, configured={"10.0.0.2": False}),
                   destination=res("destination", Status.FAIL, ip_probe_ok=True))
    ok(diagnose(dns_bad).verdict == "DNS server not responding", "dns verdict")
    apipa = dict(good, local_ip=res("local_ip", Status.FAIL, apipa=True))
    ok("DHCP" in diagnose(apipa).verdict, "apipa verdict")
    router = dict(good, gateway_ping=res("gateway_ping", Status.FAIL),
                  destination=res("destination", Status.FAIL, ip_probe_ok=False),
                  dns=res("dns", Status.FAIL, public_ok=False))
    ok(diagnose(router).verdict == "Cannot reach the network's router", "router verdict")
    slow = dict(good, quality=res("quality", Status.WARN))
    ok(diagnose(slow).verdict.startswith("Connected, but slow"), "slow verdict")

    print(f"selftest passed ({n} checks)")
    return 0


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="First-line network troubleshooting.")
    p.add_argument("-v", "--verbose", action="store_true", help="show details and raw command output (for IT)")
    p.add_argument("--json", action="store_true", help="print the full report as JSON and nothing else")
    p.add_argument("--config", type=Path, help="path to a netdiag.toml settings file")
    p.add_argument("--host", help="approved destination host (overrides settings)")
    p.add_argument("--port", type=int, help="approved destination port (overrides settings)")
    p.add_argument("--report-dir", help="folder for saved reports")
    p.add_argument("--no-report", action="store_true", help="do not save report files")
    p.add_argument("--no-trace", action="store_true", help="never run tracert/traceroute")
    p.add_argument("--no-pause", action="store_true", help="do not wait for Enter at the end")
    p.add_argument("--init-config", nargs="?", const="netdiag.toml", metavar="PATH",
                   help="write a sample settings file and exit")
    p.add_argument("--selftest", action="store_true", help="run built-in parser tests and exit")
    p.add_argument("--version", action="version", version=f"netdiag {__version__}")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    if args.selftest:
        return selftest()
    if args.init_config:
        target = Path(args.init_config)
        if target.exists():
            print(f"{target} already exists - not overwriting.", file=sys.stderr)
            return 3
        target.write_text(sample_config(), encoding="utf-8")
        print(f"Wrote {target}")
        return 0

    try:
        cfg, cfg_source = load_config(args.config)
    except (OSError, tomllib.TOMLDecodeError) as e:
        print(f"Could not read settings: {e}", file=sys.stderr)
        return 3
    if args.host:
        cfg.destination_host = args.host
    if args.port:
        cfg.destination_port = args.port
    if args.report_dir:
        cfg.report_dir = args.report_dir

    ui = Console(color=enable_ansi(), quiet=args.json, verbose=args.verbose)
    host = socket.gethostname()
    ui.header(host)

    # Deliberately not asyncio.run(): a resolver thread stuck on a dead DNS server
    # must not delay exit (see os._exit in __main__).
    loop = asyncio.new_event_loop()
    try:
        results = loop.run_until_complete(run_diagnostics(cfg, ui, trace=not args.no_trace))
    except Exception as e:  # last resort - never leave staff with a traceback
        print(f"netdiag failed unexpectedly: {type(e).__name__}: {e}", file=sys.stderr)
        return 3

    diagnosis = diagnose(results)
    when = datetime.now().astimezone()
    data = build_json(results, diagnosis, cfg, cfg_source, when)
    files: list[str] = []
    if not args.no_report:
        files = save_reports(render_text_report(results, diagnosis, cfg, cfg_source, when),
                             data, cfg, host, when)
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        ui.verdict(diagnosis, files)
    return exit_code(diagnosis)


if __name__ == "__main__":
    code = main()
    if getattr(sys, "frozen", False) and len(sys.argv) == 1 and sys.stdin and sys.stdin.isatty():
        input("Press Enter to close...")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
