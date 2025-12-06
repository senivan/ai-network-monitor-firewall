# main.py
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
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

# -------------------------
# Types
# -------------------------

DirectionType = Literal["inbound", "outbound"]
ProtoType = Literal["tcp", "udp", "icmp", "any"]
RuleActionType = Literal["allow", "block"]

# -------------------------
# Global state
# -------------------------

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

# -------------------------
# Models
# -------------------------


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

    # Free-form metadata bucket
    meta: dict = Field(default_factory=dict)


class TrafficEvent(TrafficEventCreate):
    id: int
    timestamp: datetime
    decision: FirewallDecision


class SnifferEvent(BaseModel):
    # Mandatory fields from sniffer
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: ProtoType = "any"

    # Optional direction hint. If absent, we infer.
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


# -------------------------
# Helpers
# -------------------------


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


# -------------------------
# FastAPI endpoints
# -------------------------


@app.get("/health")
def health():
    return {"status": "ok"}


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

    # Update DNS mapping if present
    augment_dns_mapping(tmp)

    # Direction: from sniffer if valid, else infer from IPs
    if ev.direction in ("inbound", "outbound"):
        tmp.direction = ev.direction
    else:
        tmp.direction = infer_direction_from_ips(str(ev.src_ip), str(ev.dst_ip))

    # Hostnames & Geo
    augment_hostnames(tmp)
    augment_geo(tmp)

    decision = decide_traffic_internal(tmp)
    log_event_internal(tmp, decision)
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
        return r


# ----- Admin helper endpoints (add / delete / toggle rules) -----


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
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin/toggle-rule")
def admin_toggle_rule(rule_id: int):
    with rules_lock:
        r = rules.get(rule_id)
        if r:
            r.action = "allow" if r.action == "block" else "block"
            rules[rule_id] = r
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
            + (f" (rule {ev.decision.matched_rule_id})" if ev.decision.matched_rule_id else "")
            + "</td>"
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

    blocked_list_html = ""
    if blocked_dst:
        blocked_list_html = "<ul>" + "".join(f"<li>{ip}</li>" for ip in blocked_dst) + "</ul>"
    else:
        blocked_list_html = "<p>None</p>"

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
    log.info("AI Firewall control plane started")
