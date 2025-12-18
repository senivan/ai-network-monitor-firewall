# main.py
from __future__ import annotations

import csv
import ipaddress
import logging
import os
import socket
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict, List, Literal, Optional

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field, IPvAnyAddress

# Optional GeoIP: install geoip2 + GeoLite DB if you care
try:
    import geoip2.database  # type: ignore

    GEOIP_READER = geoip2.database.Reader("./GeoLite2-City.mmdb")
except Exception:
    GEOIP_READER = None

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ai_firewall")

app = FastAPI(title="AI Firewall Control Plane")


DirectionType = Literal["inbound", "outbound"]
ProtoType = Literal["tcp", "udp", "icmp", "any"]
RuleActionType = Literal["allow", "block"]
MlLabelType = Literal["normal", "anomaly"]

events_lock = threading.Lock()
events: Dict[int, "TrafficEvent"] = {}
_event_counter = 0

rules_lock = threading.Lock()
rules: Dict[int, "FirewallRule"] = {}
_rule_counter = 0

dns_lock = threading.Lock()
dns_cache: Dict[str, str] = {}  # ip -> hostname

local_ips_lock = threading.Lock()
local_ips: set[str] = set()

# ML verdicts (external worker)
ml_verdicts_lock = threading.Lock()
ml_verdicts: Dict[int, "MlVerdict"] = {}

# ML auto-block config
ML_AUTOBLOCK_ENABLED = os.environ.get("AI_FW_ML_AUTOBLOCK", "true").lower() == "true"
ML_AUTOBLOCK_THRESHOLD = float(os.environ.get("AI_FW_ML_AUTOBLOCK_THRESHOLD", "0.69"))

# ML warmup & unblocking
APP_START_TIME = datetime.utcnow()
ML_WARMUP_SECONDS = int(os.environ.get("AI_FW_ML_WARMUP_SECONDS", "120"))
ML_UNBLOCK_NORMAL_COUNT = int(os.environ.get("AI_FW_ML_UNBLOCK_NORMAL_COUNT", "5"))

# Track ML-based blocks per dst
# key: (dst_ip, dst_port_or_0, proto)
# value: {"rule_ids": set[int], "normal_count": int, "last_label": str, "last_score": float, "last_update": datetime}
ml_block_state_lock = threading.Lock()
ml_block_state: Dict[tuple, dict] = {}

# iptables integration
IPTABLES_AVAILABLE = False

# CSV dump config
CSV_DIR = os.environ.get("AI_FW_CSV_DIR", "./event_logs")
CSV_INTERVAL = int(os.environ.get("AI_FW_CSV_INTERVAL", "900"))  # seconds, 15 min default


class FirewallRuleBase(BaseModel):
    description: Optional[str] = None
    direction: Optional[DirectionType] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[ProtoType] = None

    action: RuleActionType = "allow"


class FirewallRule(FirewallRuleBase):
    id: int


class FirewallDecision(BaseModel):
    action: RuleActionType
    matched_rule_id: Optional[int] = None


class TrafficEventCreate(BaseModel):
    # Core
    direction: DirectionType
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: ProtoType = "any"

    # L2 / L3 / L4 info
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    iface: Optional[str] = None
    vlan_id: Optional[int] = None
    packet_len: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_tos: Optional[int] = None
    tcp_flags: Optional[str] = None

    # Hostnames
    src_hostname: Optional[str] = None
    dst_hostname: Optional[str] = None

    # DNS mapping (sniffer can send this later)
    dns_qname: Optional[str] = None
    dns_answer_ip: Optional[IPvAnyAddress] = None

    # TLS SNI from sniffer
    tls_sni: Optional[str] = None

    # GeoIP
    dst_geo_country: Optional[str] = None
    dst_geo_city: Optional[str] = None
    dst_geo_asn: Optional[int] = None
    dst_geo_org: Optional[str] = None

    # nDPI metadata
    ndpi_app_proto: Optional[str] = None
    ndpi_master_proto: Optional[str] = None
    ndpi_category: Optional[str] = None

    meta: dict = Field(default_factory=dict)


class TrafficEvent(TrafficEventCreate):
    id: int
    timestamp: datetime
    decision: FirewallDecision


class SnifferEvent(BaseModel):
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: ProtoType = "any"

    direction: Optional[DirectionType] = None

    # L2/L3/L4
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    iface: Optional[str] = None
    vlan_id: Optional[int] = None
    packet_len: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_tos: Optional[int] = None
    tcp_flags: Optional[str] = None

    # DNS enrichment (if sniffer parses DNS later)
    dns_qname: Optional[str] = None
    dns_answer_ip: Optional[IPvAnyAddress] = None

    # TLS SNI from ClientHello
    tls_sni: Optional[str] = None

    # nDPI outputs
    ndpi_app_proto: Optional[str] = None
    ndpi_master_proto: Optional[str] = None
    ndpi_category: Optional[str] = None

    # Optional timestamp from sniffer (ms since epoch)
    timestamp_ms: Optional[int] = None


class MlVerdict(BaseModel):
    event_id: int
    model: Optional[str] = None
    raw_error: Optional[float] = None
    score: float
    label: MlLabelType



def _iptables_run(args: List[str]) -> bool:
    cmd = ["/usr/sbin/iptables"] + args
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            log.warning("[iptables] %s failed: %s", " ".join(cmd), res.stderr.strip())
            return False
        return True
    except FileNotFoundError:
        log.error("[iptables] iptables command not found – dataplane disabled")
        return False
    except Exception as e:
        log.error("[iptables] error running %s: %s", " ".join(cmd), e)
        return False


def _iptables_chain_exists(name: str) -> bool:
    try:
        res = subprocess.run(
            ["/usr/sbin/iptables", "-nL", name], capture_output=True, text=True
        )
        return res.returncode == 0
    except Exception:
        return False


def _iptables_chain_has_jump(chain: str, target: str) -> bool:
    try:
        res = subprocess.run(
            ["/usr/sbin/iptables", "-nL", chain], capture_output=True, text=True
        )
        if res.returncode != 0:
            return False
        return target in res.stdout
    except Exception:
        return False


def ensure_base_chains():
    # Create custom chains if they don't exist
    if not _iptables_chain_exists("AI_FIREWALL_IN"):
        _iptables_run(["-N", "AI_FIREWALL_IN"])
    if not _iptables_chain_exists("AI_FIREWALL_OUT"):
        _iptables_run(["-N", "AI_FIREWALL_OUT"])

    if not _iptables_chain_has_jump("INPUT", "AI_FIREWALL_IN"):
        _iptables_run(["-I", "INPUT", "1", "-j", "AI_FIREWALL_IN"])
    if not _iptables_chain_has_jump("OUTPUT", "AI_FIREWALL_OUT"):
        _iptables_run(["-I", "OUTPUT", "1", "-j", "AI_FIREWALL_OUT"])


def _iptables_flush_chain(name: str):
    _iptables_run(["-F", name])


def _build_match_args(r: FirewallRule) -> List[str]:
    args: List[str] = []
    if r.protocol and r.protocol != "any":
        args += ["-p", r.protocol]
    if r.src_ip:
        args += ["-s", r.src_ip]
    if r.dst_ip:
        args += ["-d", r.dst_ip]
    if r.src_port and (not r.protocol or r.protocol in ("tcp", "udp")):
        args += ["--sport", str(r.src_port)]
    if r.dst_port and (not r.protocol or r.protocol in ("tcp", "udp")):
        args += ["--dport", str(r.dst_port)]
    return args


def rebuild_iptables_from_rules():
    global IPTABLES_AVAILABLE
    if not IPTABLES_AVAILABLE:
        return

    log.info("[iptables] Rebuilding AI firewall chains from rules")

    ensure_base_chains()
    _iptables_flush_chain("AI_FIREWALL_IN")
    _iptables_flush_chain("AI_FIREWALL_OUT")

    with rules_lock:
        all_rules = list(rules.values())

    for r in all_rules:
        if r.action != "block":
            continue

        match_args = _build_match_args(r)

        # direction controls which chain we place rule into
        if r.direction == "inbound":
            chains = ["AI_FIREWALL_IN"]
        elif r.direction == "outbound":
            chains = ["AI_FIREWALL_OUT"]
        else:
            chains = ["AI_FIREWALL_IN", "AI_FIREWALL_OUT"]

        for chain in chains:
            ok = _iptables_run(["-A", chain] + match_args + ["-j", "DROP"])
            if not ok:
                log.warning(
                    "[iptables] Failed to install rule %d into %s", r.id, chain
                )


def init_iptables():
    global IPTABLES_AVAILABLE
    try:
        res = subprocess.run(["/usr/sbin/iptables", "-L"], capture_output=True, text=True)
        if res.returncode != 0:
            log.warning(
                "[iptables] iptables present but returned error: %s",
                res.stderr.strip(),
            )
            IPTABLES_AVAILABLE = False
            return
        IPTABLES_AVAILABLE = True
        log.info("[iptables] iptables detected, enabling dataplane integration")
    except FileNotFoundError:
        log.warning("[iptables] iptables not found, dataplane integration disabled")
        IPTABLES_AVAILABLE = False
        return

    ensure_base_chains()
    rebuild_iptables_from_rules()



def detect_local_ips() -> set[str]:
    """Collect local IPv4 addresses from hostname resolution."""
    ips: set[str] = set()
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(socket.gethostname(), None):
            if fam == socket.AF_INET:
                ips.add(sockaddr[0])
        ips.add("127.0.0.1")
    except Exception as e:
        log.warning("Failed to detect local IPs: %s", e)
    return ips


def infer_direction_from_ips(src: str, dst: str) -> DirectionType:
    """
    Very simple: private -> public = outbound, public -> private = inbound.
    Anything else defaults to outbound.
    """
    try:
        src_ip = ipaddress.ip_address(src)
        dst_ip = ipaddress.ip_address(dst)
    except ValueError:
        return "outbound"

    def is_local(addr: ipaddress._BaseAddress) -> bool:
        with local_ips_lock:
            if str(addr) in local_ips:
                return True
        return addr.is_private

    src_local = is_local(src_ip)
    dst_local = is_local(dst_ip)

    if src_local and not dst_local:
        return "outbound"
    if not src_local and dst_local:
        return "inbound"
    return "outbound"


def augment_dns_mapping(ev: TrafficEventCreate) -> None:
    if ev.dns_qname and ev.dns_answer_ip:
        ip_str = str(ev.dns_answer_ip)
        with dns_lock:
            dns_cache[ip_str] = ev.dns_qname


def augment_hostnames(ev: TrafficEventCreate) -> None:
    # Prefer explicit TLS SNI
    if ev.tls_sni and not ev.dst_hostname:
        ev.dst_hostname = ev.tls_sni

    # Fallback to DNS cache
    if not ev.dst_hostname:
        ip_str = str(ev.dst_ip)
        with dns_lock:
            hn = dns_cache.get(ip_str)
        if hn:
            ev.dst_hostname = hn


def augment_geo(ev: TrafficEventCreate) -> None:
    if GEOIP_READER is None:
        return
    try:
        ip_str = str(ev.dst_ip)
        resp = GEOIP_READER.city(ip_str)
        ev.dst_geo_country = resp.country.iso_code or None
        ev.dst_geo_city = resp.city.name or None
        if resp.traits.autonomous_system_number:
            ev.dst_geo_asn = resp.traits.autonomous_system_number
        if resp.traits.autonomous_system_organization:
            ev.dst_geo_org = resp.traits.autonomous_system_organization
    except Exception:
        # best-effort only
        pass


def decide_traffic_internal(ev: TrafficEventCreate) -> FirewallDecision:
    """
    Extremely simple rule engine: first matching rule wins.
    If no rule matches, default allow.
    """
    with rules_lock:
        all_rules = list(rules.values())

    for r in all_rules:
        if r.direction and r.direction != ev.direction:
            continue
        if r.protocol and r.protocol != ev.protocol and r.protocol != "any":
            continue
        if r.src_ip and r.src_ip != str(ev.src_ip):
            continue
        if r.dst_ip and r.dst_ip != str(ev.dst_ip):
            continue
        if r.src_port and r.src_port != ev.src_port:
            continue
        if r.dst_port and r.dst_port != ev.dst_port:
            continue

        return FirewallDecision(action=r.action, matched_rule_id=r.id)

    return FirewallDecision(action="allow", matched_rule_id=None)


def log_event_internal(ev: TrafficEventCreate, decision: FirewallDecision) -> TrafficEvent:
    global _event_counter
    with events_lock:
        _event_counter += 1
        eid = _event_counter
        te = TrafficEvent(
            id=eid,
            timestamp=datetime.utcnow(),
            decision=decision,
            **ev.dict(),
        )
        events[eid] = te
        return te


def _ml_block_key(ev: TrafficEvent) -> tuple:
    return (str(ev.dst_ip), ev.dst_port or 0, ev.protocol)


def register_ml_block(ev: TrafficEvent, rule_id: int, score: float):
    key = _ml_block_key(ev)
    now = datetime.utcnow()
    with ml_block_state_lock:
        st = ml_block_state.get(key)
        if not st:
            st = {
                "rule_ids": set(),
                "normal_count": 0,
                "last_label": "anomaly",
                "last_score": score,
                "last_update": now,
            }
            ml_block_state[key] = st
        st["rule_ids"].add(rule_id)
        st["normal_count"] = 0
        st["last_label"] = "anomaly"
        st["last_score"] = score
        st["last_update"] = now


def update_ml_block_on_anomaly(ev: TrafficEvent, score: float):
    key = _ml_block_key(ev)
    now = datetime.utcnow()
    with ml_block_state_lock:
        st = ml_block_state.get(key)
        if not st:
            st = {
                "rule_ids": set(),
                "normal_count": 0,
                "last_label": "anomaly",
                "last_score": score,
                "last_update": now,
            }
            ml_block_state[key] = st
        st["normal_count"] = 0
        st["last_label"] = "anomaly"
        st["last_score"] = score
        st["last_update"] = now


def update_ml_block_on_normal(ev: TrafficEvent, score: float):
    key = _ml_block_key(ev)
    now = datetime.utcnow()
    with ml_block_state_lock:
        st = ml_block_state.get(key)
        if not st:
            return
        st["normal_count"] += 1
        st["last_label"] = "normal"
        st["last_score"] = score
        st["last_update"] = now
        normal_count = st["normal_count"]
        rule_ids = list(st["rule_ids"])

    if normal_count < ML_UNBLOCK_NORMAL_COUNT:
        return

    # Enough normals – remove ML auto-block rules
    with rules_lock:
        for rid in rule_ids:
            r = rules.get(rid)
            if not r:
                continue
            if not r.description or not r.description.startswith("ML auto-block"):
                continue
            del rules[rid]

    with ml_block_state_lock:
        ml_block_state.pop(key, None)

    rebuild_iptables_from_rules()
    log.info(
        "ML unblocked dst=%s port=%s proto=%s after %d normal verdicts",
        key[0],
        key[1] or "any",
        key[2],
        ML_UNBLOCK_NORMAL_COUNT,
    )


def create_ml_autoblock_rule_for_event(ev: TrafficEvent, score: float) -> Optional[FirewallRule]:
    """
    Create a simple block rule for this event's destination if none exists.
    """
    global _rule_counter

    dst_ip = str(ev.dst_ip)
    if not dst_ip:
        return None

    with rules_lock:
        # avoid spamming identical rules
        for r in rules.values():
            if (
                r.action == "block"
                and r.dst_ip == dst_ip
                and (r.dst_port == ev.dst_port or r.dst_port is None)
                and (r.protocol == ev.protocol or r.protocol is None or r.protocol == "any")
                and r.description
                and r.description.startswith("ML auto-block")
            ):
                # already have an ML block for this dst
                return None

        _rule_counter += 1
        new_rule = FirewallRule(
            id=_rule_counter,
            description=f"ML auto-block (score={score:.3f}) dst={dst_ip}",
            direction=ev.direction,
            src_ip=None,
            dst_ip=dst_ip,
            src_port=None,
            dst_port=ev.dst_port,
            protocol=ev.protocol,
            action="block",
        )
        rules[new_rule.id] = new_rule

    register_ml_block(ev, new_rule.id, score)

    log.info(
        "Created ML auto-block rule %d for event %d (dst=%s, score=%.3f)",
        new_rule.id,
        ev.id,
        dst_ip,
        score,
    )
    return new_rule


def csv_dump_loop():
    os.makedirs(CSV_DIR, exist_ok=True)
    log.info("CSV dumping enabled: dir=%s interval=%ds", CSV_DIR, CSV_INTERVAL)
    last_cut = datetime.utcnow()

    while True:
        time.sleep(CSV_INTERVAL)
        now = datetime.utcnow()

        with events_lock:
            slice_events = [
                e for e in events.values()
                if last_cut <= e.timestamp < now
            ]

        if not slice_events:
            last_cut = now
            continue

        # snapshot ML verdicts
        with ml_verdicts_lock:
            mv_map = dict(ml_verdicts)

        filename = f"events_{last_cut.strftime('%Y%m%d_%H%M%S')}_{now.strftime('%Y%m%d_%H%M%S')}.csv"
        path = os.path.join(CSV_DIR, filename)

        try:
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(
                    [
                        "id",
                        "timestamp",
                        "direction",
                        "src_ip",
                        "dst_ip",
                        "src_port",
                        "dst_port",
                        "protocol",
                        "src_mac",
                        "dst_mac",
                        "packet_len",
                        "ip_ttl",
                        "ip_tos",
                        "ndpi_master_proto",
                        "ndpi_app_proto",
                        "ndpi_category",
                        "dst_geo_country",
                        "dst_geo_city",
                        "tls_sni",
                        "dns_qname",
                        "dns_answer_ip",
                        "ml_label",
                        "ml_score",
                    ]
                )
                for e in sorted(slice_events, key=lambda x: x.id):
                    mv = mv_map.get(e.id)
                    ml_label = mv.label if mv else e.meta.get("ml_label")
                    ml_score = mv.score if mv else e.meta.get("ml_score")
                    w.writerow(
                        [
                            e.id,
                            e.timestamp.isoformat(),
                            e.direction,
                            str(e.src_ip),
                            str(e.dst_ip),
                            e.src_port or "",
                            e.dst_port or "",
                            e.protocol,
                            e.src_mac or "",
                            e.dst_mac or "",
                            e.packet_len or "",
                            e.ip_ttl or "",
                            e.ip_tos or "",
                            e.ndpi_master_proto or "",
                            e.ndpi_app_proto or "",
                            e.ndpi_category or "",
                            e.dst_geo_country or "",
                            e.dst_geo_city or "",
                            e.tls_sni or "",
                            e.dns_qname or "",
                            str(e.dns_answer_ip) if e.dns_answer_ip else "",
                            ml_label or "",
                            f"{ml_score:.6f}" if isinstance(ml_score, (int, float)) else "",
                        ]
                    )
            log.info("Dumped %d events to %s", len(slice_events), path)
        except Exception as exc:
            log.error("Failed to write CSV %s: %s", path, exc)

        last_cut = now



@app.get("/health")
def health():
    warmup_left = max(
        0,
        ML_WARMUP_SECONDS - int((datetime.utcnow() - APP_START_TIME).total_seconds()),
    )
    return {
        "status": "ok",
        "ml_autoblock": ML_AUTOBLOCK_ENABLED,
        "ml_threshold": ML_AUTOBLOCK_THRESHOLD,
        "ml_warmup_seconds_left": warmup_left,
    }


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>AI Firewall – Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        body { font-family: sans-serif; background: #111; color: #eee; padding: 20px; }
        select { background:#222; color:#eee; border:1px solid #555; padding:6px; }
        canvas { background:#0d0d0d; margin-top:20px; }
    </style>
</head>

<body>

<h1>User activity dashboard</h1>

<label>User (src IP): </label>
<select id="userSelect"></select>

<h3>Traffic categories</h3>
<canvas id="catChart" height="120"></canvas>

<h3>Timeline</h3>
<canvas id="timeChart" height="120"></canvas>

<script>
let catChart = null;
let timeChart = null;

async function loadUsers() {
    const res = await fetch("/users");
    const users = await res.json();

    const sel = document.getElementById("userSelect");
    sel.innerHTML = "";

    users.forEach(ip => {
        const o = document.createElement("option");
        o.value = ip;
        o.textContent = ip;
        sel.appendChild(o);
    });

    if (users.length > 0) {
        sel.value = users[0];
        loadActivity();
    }
}

async function loadActivity() {
    const ip = document.getElementById("userSelect").value;
    if (!ip) return;

    const res = await fetch("/users/" + ip + "/activity");
    const data = await res.json();

    // ---- BAR ----
    if (catChart) catChart.destroy();
    catChart = new Chart(document.getElementById("catChart"), {
        type: "bar",
        data: {
            labels: Object.keys(data.categories),
            datasets: [{
                label: "Connections",
                data: Object.values(data.categories),
                backgroundColor: "#3fa9f5"
            }]
        },
        options: { scales: { y: { beginAtZero: true } } }
    });

    // ---- LINE ----
    if (timeChart) timeChart.destroy();
    timeChart = new Chart(document.getElementById("timeChart"), {
        type: "line",
        data: {
            labels: data.timeline.map(p => p.time),
            datasets: [{
                label: "Events",
                data: data.timeline.map(p => p.count),
                borderColor: "#00e676",
                tension: 0.3,
                fill: false
            }]
        },
        options: { scales: { y: { beginAtZero: true } } }
    });
}

document.getElementById("userSelect").addEventListener("change", loadActivity);
loadUsers();
</script>

</body>
</html>
"""
    return HTMLResponse(html)

@app.get("/users")
def users():
    with events_lock:
        return sorted({str(e.src_ip) for e in events.values()})



@app.get("/users/{ip}/activity")
def user_activity(ip: str):
    from collections import Counter, defaultdict

    with events_lock:
        evs = [e for e in events.values() if str(e.src_ip) == ip]

    categories = Counter(e.ndpi_category or "Unknown" for e in evs)

    timeline = defaultdict(int)
    for e in evs:
        t = e.timestamp.strftime("%H:%M")
        timeline[t] += 1

    return {
        "categories": categories,
        "timeline": [
            {"time": k, "count": v}
            for k, v in sorted(timeline.items())
        ]
    }


@app.post("/sniffer-events", status_code=204)
def ingest_sniffer_event(ev: SnifferEvent):
    log.info("sniffer event: %s -> %s proto=%s", ev.src_mac, ev.dst_mac, ev.protocol)

    # Build a TrafficEventCreate
    tmp = TrafficEventCreate(
        direction="outbound",  # provisional, will correct below
        src_ip=ev.src_ip,
        dst_ip=ev.dst_ip,
        src_port=ev.src_port,
        dst_port=ev.dst_port,
        protocol=ev.protocol,
        src_mac=ev.src_mac,
        dst_mac=ev.dst_mac,
        iface=ev.iface,
        vlan_id=ev.vlan_id,
        packet_len=ev.packet_len,
        ip_ttl=ev.ip_ttl,
        ip_tos=ev.ip_tos,
        tcp_flags=ev.tcp_flags,
        dns_qname=ev.dns_qname,
        dns_answer_ip=ev.dns_answer_ip,
        tls_sni=ev.tls_sni,
        ndpi_app_proto=ev.ndpi_app_proto,
        ndpi_master_proto=ev.ndpi_master_proto,
        ndpi_category=ev.ndpi_category,
        meta={"source": "cpp-sniffer", "timestamp_ms": ev.timestamp_ms},
    )

    augment_dns_mapping(tmp)

    if ev.direction in ("inbound", "outbound"):
        tmp.direction = ev.direction
    else:
        tmp.direction = infer_direction_from_ips(str(ev.src_ip), str(ev.dst_ip))

    augment_hostnames(tmp)
    augment_geo(tmp)

    decision = decide_traffic_internal(tmp)
    log_event_internal(tmp, decision)
    return


@app.post("/ml/verdicts", status_code=204)
def ingest_ml_verdict(v: MlVerdict):
    """
    Endpoint for the external ML worker.

    Worker sends:
        {
          "event_id": int,
          "model": "lstm_ae",
          "raw_error": float,
          "score": float,
          "label": "normal" | "anomaly"
        }
    """
    now = datetime.utcnow()
    warmup = (now - APP_START_TIME).total_seconds() < ML_WARMUP_SECONDS

    with ml_verdicts_lock:
        ml_verdicts[v.event_id] = v

    # Enrich event, if present
    with events_lock:
        ev = events.get(v.event_id)
        if ev:
            ev.meta["ml_score"] = v.score
            ev.meta["ml_label"] = v.label
            ev.meta["ml_model"] = v.model or "unknown"
            ev.meta["ml_raw_error"] = v.raw_error

    log.info(
        "ML verdict for event %s: label=%s score=%.3f model=%s (warmup=%s)",
        v.event_id,
        v.label,
        v.score,
        v.model or "n/a",
        warmup,
    )

    if not ev:
        return

    # Handle anomaly / normal with warmup + temporary blocks
    if v.label == "anomaly":
        # During warmup, don't auto-block at all
        if ML_AUTOBLOCK_ENABLED and not warmup and v.score >= ML_AUTOBLOCK_THRESHOLD:
            new_rule = create_ml_autoblock_rule_for_event(ev, v.score)
            if new_rule:
                rebuild_iptables_from_rules()
        else:
            # no rule created, but we still track anomaly state
            update_ml_block_on_anomaly(ev, v.score)
    elif v.label == "normal":
        # Count consecutive normals and potentially unblock
        update_ml_block_on_normal(ev, v.score)

    return


@app.get("/events", response_model=List[TrafficEvent])
def list_events(
    limit: int = Query(100, ge=1, le=1000),
    direction: Optional[DirectionType] = None,
):
    with events_lock:
        ordered = sorted(events.values(), key=lambda e: e.id, reverse=True)

    if direction:
        ordered = [e for e in ordered if e.direction == direction]

    return ordered[:limit]


@app.get("/rules", response_model=List[FirewallRule])
def list_rules():
    with rules_lock:
        return sorted(rules.values(), key=lambda r: r.id)


@app.post("/rules", response_model=FirewallRule)
def create_rule(rule: FirewallRuleBase):
    global _rule_counter
    with rules_lock:
        _rule_counter += 1
        r = FirewallRule(id=_rule_counter, **rule.dict())
        rules[r.id] = r
    rebuild_iptables_from_rules()
    return r




@app.get("/admin/add-rule")
def admin_add_rule(
    description: str = "",
    direction: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    action: str = "block",
):
    dir_val: Optional[DirectionType] = None
    if direction in ("inbound", "outbound"):
        dir_val = direction  # type: ignore

    proto_val: Optional[ProtoType] = None
    if protocol in ("tcp", "udp", "icmp", "any"):
        proto_val = protocol  # type: ignore

    rule_base = FirewallRuleBase(
        description=description or None,
        direction=dir_val,
        src_ip=src_ip or None,
        dst_ip=dst_ip or None,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto_val,
        action="block" if action == "block" else "allow",
    )
    create_rule(rule_base)
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin/delete-rule")
def admin_delete_rule(rule_id: int):
    with rules_lock:
        if rule_id in rules:
            del rules[rule_id]
    rebuild_iptables_from_rules()
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin/toggle-rule")
def admin_toggle_rule(rule_id: int):
    with rules_lock:
        r = rules.get(rule_id)
        if r:
            r.action = "allow" if r.action == "block" else "block"
            rules[r.id] = r
    rebuild_iptables_from_rules()
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
def admin_page(limit: int = 200):
    # Events
    with events_lock:
        ordered = sorted(events.values(), key=lambda e: e.id, reverse=True)[:limit]

    # Rules
    with rules_lock:
        all_rules = sorted(rules.values(), key=lambda r: r.id)

    # Build “blocked destinations” set
    blocked_dst = sorted(
        {r.dst_ip for r in all_rules if r.action == "block" and r.dst_ip}
    )

    # Event rows
    event_rows = []
    for ev in ordered:
        src_label = f"{ev.src_ip}"
        dst_label = f"{ev.dst_ip}"

        if ev.src_hostname:
            src_label += f" ({ev.src_hostname})"
        if ev.dst_hostname:
            dst_label += f" ({ev.dst_hostname})"
        elif ev.tls_sni:
            dst_label += f" ({ev.tls_sni})"

        mac_info = ""
        if ev.src_mac or ev.dst_mac:
            mac_info = f"{ev.src_mac or ''} → {ev.dst_mac or ''}"

        ndpi_parts: List[str] = []
        if ev.ndpi_master_proto:
            ndpi_parts.append(ev.ndpi_master_proto)
        if ev.ndpi_app_proto:
            ndpi_parts.append(ev.ndpi_app_proto)
        if ev.ndpi_category:
            ndpi_parts.append(f"[{ev.ndpi_category}]")
        ndpi_info = " ".join(ndpi_parts)

        geo_info = ""
        if ev.dst_geo_country:
            geo_info = ev.dst_geo_country
            if ev.dst_geo_city:
                geo_info += f", {ev.dst_geo_city}"

        # ML info
        with ml_verdicts_lock:
            mv = ml_verdicts.get(ev.id)
        if mv:
            ml_info = f"{mv.label} ({mv.score:.3f})"
        else:
            if "ml_label" in ev.meta:
                try:
                    s = float(ev.meta.get("ml_score", 0.0))
                    ml_info = f"{ev.meta['ml_label']} ({s:.3f})"
                except Exception:
                    ml_info = str(ev.meta.get("ml_label", ""))
            else:
                ml_info = ""

        event_rows.append(
            f"<tr>"
            f"<td>{ev.id}</td>"
            f"<td>{ev.timestamp.isoformat()}</td>"
            f"<td>{ev.direction}</td>"
            f"<td>{src_label}</td>"
            f"<td>{dst_label}</td>"
            f"<td>{ev.protocol.upper()}</td>"
            f"<td>{ev.src_port or ''}</td>"
            f"<td>{ev.dst_port or ''}</td>"
            f"<td>{mac_info}</td>"
            f"<td>{ev.tcp_flags or ''}</td>"
            f"<td>{ndpi_info}</td>"
            f"<td>{geo_info}</td>"
            f"<td>{ev.decision.action}"
            + (
                f" (rule {ev.decision.matched_rule_id})"
                if ev.decision.matched_rule_id
                else ""
            )
            + "</td>"
            f"<td>{ml_info}</td>"
            f"</tr>"
        )

    # Rule rows
    rule_rows = []
    for r in all_rules:
        rule_rows.append(
            f"<tr>"
            f"<td>{r.id}</td>"
            f"<td>{r.action.upper()}</td>"
            f"<td>{r.direction or ''}</td>"
            f"<td>{r.protocol or ''}</td>"
            f"<td>{r.src_ip or ''}</td>"
            f"<td>{r.dst_ip or ''}</td>"
            f"<td>{r.src_port or ''}</td>"
            f"<td>{r.dst_port or ''}</td>"
            f"<td>{r.description or ''}</td>"
            f"<td>"
            f"<a href='/admin/toggle-rule?rule_id={r.id}'>toggle</a> | "
            f"<a href='/admin/delete-rule?rule_id={r.id}'>delete</a>"
            f"</td>"
            f"</tr>"
        )

    blocked_list_html = (
        "<ul>" + "".join(f"<li>{ip}</li>" for ip in blocked_dst) + "</ul>"
        if blocked_dst
        else "<p>None</p>"
    )

    warmup_left = max(
        0,
        ML_WARMUP_SECONDS - int((datetime.utcnow() - APP_START_TIME).total_seconds()),
    )

    html = f"""
    <html>
    <head>
        <title>AI Firewall Admin</title>
        <style>
        body {{ font-family: sans-serif; background: #111; color: #eee; }}
        h1, h2, h3 {{ margin-top: 1rem; }}
        table {{ border-collapse: collapse; width: 100%; font-size: 12px; }}
        th, td {{ border: 1px solid #444; padding: 4px 6px; }}
        th {{ background: #222; position: sticky; top: 0; }}
        tr:nth-child(even) {{ background: #181818; }}
        tr:nth-child(odd) {{ background: #101010; }}
        input, select {{ background:#222; color:#eee; border:1px solid #555; padding:3px; font-size:12px; }}
        </style>
    </head>
    <body>
        <h1>AI Firewall – Admin</h1>

        <h2>ML status</h2>
        <p>
            ML auto-block: <b>{'ENABLED' if ML_AUTOBLOCK_ENABLED else 'DISABLED'}</b>,
            threshold: <b>{ML_AUTOBLOCK_THRESHOLD:.2f}</b><br/>
            Warmup: <b>{ML_WARMUP_SECONDS}s</b>,
            remaining: <b>{warmup_left}s</b><br/>
            Unblock after <b>{ML_UNBLOCK_NORMAL_COUNT}</b> normal verdicts.
        </p>

        <h2>Add rule</h2>
        <form method="get" action="/admin/add-rule">
            <table>
                <tr>
                    <td>Description</td>
                    <td><input type="text" name="description" size="30"></td>
                </tr>
                <tr>
                    <td>Direction</td>
                    <td>
                        <select name="direction">
                            <option value="">(any)</option>
                            <option value="inbound">inbound</option>
                            <option value="outbound">outbound</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td>Protocol</td>
                    <td>
                        <select name="protocol">
                            <option value="">(any)</option>
                            <option value="tcp">tcp</option>
                            <option value="udp">udp</option>
                            <option value="icmp">icmp</option>
                            <option value="any">any</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td>Src IP / Port</td>
                    <td>
                        <input type="text" name="src_ip" size="15" placeholder="src_ip">
                        <input type="number" name="src_port" min="1" max="65535" placeholder="port">
                    </td>
                </tr>
                <tr>
                    <td>Dst IP / Port</td>
                    <td>
                        <input type="text" name="dst_ip" size="15" placeholder="dst_ip">
                        <input type="number" name="dst_port" min="1" max="65535" placeholder="port">
                    </td>
                </tr>
                <tr>
                    <td>Action</td>
                    <td>
                        <select name="action">
                            <option value="block">block</option>
                            <option value="allow">allow</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td colspan="2">
                        <button type="submit">Add rule</button>
                    </td>
                </tr>
            </table>
        </form>

        <h2>Rules</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Action</th>
                <th>Direction</th>
                <th>Proto</th>
                <th>Src IP</th>
                <th>Dst IP</th>
                <th>Src Port</th>
                <th>Dst Port</th>
                <th>Description</th>
                <th>Ops</th>
            </tr>
            {''.join(rule_rows)}
        </table>

        <h2>Blocked destinations (by rules)</h2>
        {blocked_list_html}

        <h2>Recent events</h2>
        <p>Showing latest {len(ordered)} events</p>
        <table>
            <tr>
                <th>ID</th>
                <th>Time (UTC)</th>
                <th>Dir</th>
                <th>Src</th>
                <th>Dst</th>
                <th>Proto</th>
                <th>Src Port</th>
                <th>Dst Port</th>
                <th>MACs</th>
                <th>TCP Flags</th>
                <th>nDPI (master/app/category)</th>
                <th>Geo</th>
                <th>Decision</th>
                <th>ML</th>
            </tr>
            {''.join(event_rows)}
        </table>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.on_event("startup")
def on_startup():
    global local_ips
    local_ips = detect_local_ips()
    log.info("Local IPs for direction detection: %s", local_ips)
    log.info("AI Firewall control plane started at %s", APP_START_TIME.isoformat())
    log.info(
        "ML auto-block: %s (threshold=%.2f, warmup=%ds, unblock_normals=%d)",
        "ENABLED" if ML_AUTOBLOCK_ENABLED else "DISABLED",
        ML_AUTOBLOCK_THRESHOLD,
        ML_WARMUP_SECONDS,
        ML_UNBLOCK_NORMAL_COUNT,
    )

    init_iptables()

    t = threading.Thread(target=csv_dump_loop, daemon=True)
    t.start()
