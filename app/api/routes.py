"""Flask API routes for the Network Traffic Analyzer."""

import ipaddress

from flask import Blueprint, jsonify, request

import database


api = Blueprint("api", __name__, url_prefix="/api")


@api.get("/health")
def health():
    """Return API health status."""
    return jsonify({
        "status": "healthy",
        "service": "network-traffic-analyzer-api",
    })


@api.get("/packets")
def get_packets():
    """Return captured packets with optional filtering.

    Supported filters:
    - protocol: TCP, UDP, or ICMP
    - source_ip: source IPv4/IPv6 address
    - destination_ip: destination IPv4/IPv6 address
    - source_port: source port (1-65535)
    - destination_port: destination port (1-65535)

    Multiple filters can be combined.
    If no filters are provided, all available packets are returned.
    """

    # Make sure the database and packets table exist.
    database.init_db()

    # Read query parameters.
    protocol = request.args.get("protocol")
    source_ip = request.args.get("source_ip")
    destination_ip = request.args.get("destination_ip")
    source_port = request.args.get("source_port")
    destination_port = request.args.get("destination_port")

    # ---------------------------------------------------------
    # Validate protocol
    # ---------------------------------------------------------
    if protocol is not None:
        protocol = protocol.upper()

        if protocol not in {"TCP", "UDP", "ICMP"}:
            return jsonify({
                "error": "Invalid protocol. Use TCP, UDP, or ICMP."
            }), 400

    # ---------------------------------------------------------
    # Validate source and destination IP addresses
    # ---------------------------------------------------------
    for ip_value, field_name in [
        (source_ip, "source_ip"),
        (destination_ip, "destination_ip"),
    ]:
        if ip_value is not None:
            try:
                ipaddress.ip_address(ip_value)
            except ValueError:
                return jsonify({
                    "error": f"Invalid {field_name}."
                }), 400

    # ---------------------------------------------------------
    # Validate ports
    # ---------------------------------------------------------
    def validate_port(value):
        """Convert a port to int and validate its range."""
        if value is None:
            return None

        try:
            port = int(value)
        except (TypeError, ValueError):
            return None

        if not 1 <= port <= 65535:
            return None

        return port

    source_port_value = validate_port(source_port)
    destination_port_value = validate_port(destination_port)

    if source_port is not None and source_port_value is None:
        return jsonify({
            "error": "Invalid source_port."
        }), 400

    if destination_port is not None and destination_port_value is None:
        return jsonify({
            "error": "Invalid destination_port."
        }), 400

    # ---------------------------------------------------------
    # Query filtered packets
    # ---------------------------------------------------------
    packets = database.get_filtered_packets(
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port_value,
        destination_port=destination_port_value,
    )

    # ---------------------------------------------------------
    # Return JSON response
    # ---------------------------------------------------------
    return jsonify({
        "packets": packets,
        "count": len(packets),
    })


@api.get("/stats")
def get_stats():
    """Return packet statistics."""
    database.init_db()

    statistics = database.get_statistics()
    protocols = statistics.get("protocols", {})

    return jsonify({
        "total_packets": statistics.get("total", 0),
        "tcp": protocols.get("TCP", 0),
        "udp": protocols.get("UDP", 0),
        "icmp": protocols.get("ICMP", 0),
    })


@api.get("/alerts")
def get_alerts():
    """Return alerts.

    Alert generation will be implemented in a later sprint.
    """
    return jsonify({
        "alerts": [],
        "count": 0,
        "message": "No alerts available"
    })