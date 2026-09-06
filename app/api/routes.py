from flask import Blueprint, jsonify


api = Blueprint("api", __name__, url_prefix="/api")


@api.get("/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "service": "network-traffic-analyzer-api",
        }
    )


@api.get("/packets")
def get_packets():
    """Return captured packets.

    Packet database integration will be added when the
    database module is implemented.
    """
    return jsonify(
        {
            "packets": [],
            "count": 0,
            "message": "Packet retrieval will be connected to the database.",
        }
    )


@api.get("/stats")
def get_stats():
    """Return traffic statistics.

    Statistics calculation will be connected to packet analysis
    and database modules in later development.
    """
    return jsonify(
        {
            "total_packets": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
        }
    )


@api.get("/alerts")
def get_alerts():
    """Return security alerts.

    Security alert integration will be added with the
    security detection module.
    """
    return jsonify(
        {
            "alerts": [],
            "count": 0,
        }
    )