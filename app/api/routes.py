"""Flask API routes for the Network Traffic Analyzer."""

import ipaddress
import re

from flask import Blueprint, jsonify, request

import database

api = Blueprint("api", __name__, url_prefix="/api")

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000

# Users may type a partial address while searching ("192.168.1", "fe80:").
_PARTIAL_IP = re.compile(
    r"^(?:[0-9]{1,3}(?:\.[0-9]{0,3}){0,3}|(?=.*:)[0-9a-fA-F:]{2,39})$"
)


class FilterError(ValueError):
    """Raised when a query parameter is invalid (returned as HTTP 400)."""


@api.errorhandler(FilterError)
def handle_filter_error(err):
    return jsonify({"error": str(err)}), 400


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_PARTIAL_IP.match(value))


def _parse_filters():
    """Validate ?protocol=&source_ip=&destination_ip=&source_port=&destination_port=."""
    args = request.args

    protocol = (args.get("protocol") or "").strip().upper() or None
    if protocol and protocol not in VALID_PROTOCOLS:
        raise FilterError("Invalid protocol. Use TCP, UDP, or ICMP.")

    filters = {"protocol": protocol}

    for field in ("source_ip", "destination_ip"):
        value = (args.get(field) or "").strip()
        if value and not _valid_ip(value):
            raise FilterError(f"Invalid {field}.")
        filters[field] = value or None

    for field in ("source_port", "destination_port"):
        raw = (args.get(field) or "").strip()
        if not raw:
            filters[field] = None
            continue
        try:
            port = int(raw)
        except ValueError:
            raise FilterError(f"Invalid {field}.") from None
        if not 1 <= port <= 65535:
            raise FilterError(f"Invalid {field}.")
        filters[field] = port

    return filters


def _parse_limit():
    raw = request.args.get("limit")
    if raw in (None, ""):
        return DEFAULT_LIMIT
    try:
        limit = int(raw)
    except ValueError:
        raise FilterError("Invalid limit.") from None
    if not 1 <= limit <= MAX_LIMIT:
        raise FilterError(f"limit must be between 1 and {MAX_LIMIT}.")
    return limit


@api.get("/health")
def health():
    """Return API health status."""
    return jsonify({"status": "healthy", "service": "network-traffic-analyzer-api"})


@api.get("/packets")
def get_packets():
    """Filtered packet list. Filters: protocol, source_ip, destination_ip,
    source_port, destination_port, limit. Combine freely."""
    filters = _parse_filters()
    limit = _parse_limit()
    packets = database.get_filtered_packets(limit=limit, **filters)
    return jsonify({"packets": packets, "count": len(packets)})


@api.get("/stats")
def get_stats():
    """Traffic statistics for the SAME filters as /api/packets."""
    filters = _parse_filters()
    s = database.get_statistics(**filters)
    protocols = s["protocols"]
    tcp, udp, icmp = (protocols.get(p, 0) for p in ("TCP", "UDP", "ICMP"))

    return jsonify({
        "total_packets": s["total"],
        "total_bytes": s["total_bytes"],
        "average_packet_size": s["average_packet_size"],
        "protocols": protocols,
        "protocol_bytes": s["protocol_bytes"],
        "tcp": tcp,
        "udp": udp,
        "icmp": icmp,
        "other": s["total"] - tcp - udp - icmp,
        "source_ports": s["source_ports"],
        "destination_ports": s["destination_ports"],
        "top_source_ips": s["top_source_ips"],
        "top_destination_ips": s["top_destination_ips"],
        "traffic_pairs": s["traffic_pairs"],
        "port_activity": s["port_activity"],
    })


@api.get("/alerts")
def get_alerts():
    """Placeholder until Sprint 4 alert generation lands."""
    return jsonify({"alerts": [], "count": 0, "message": "No alerts available"})
