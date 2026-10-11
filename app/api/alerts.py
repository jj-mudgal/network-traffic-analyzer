"""Security alerts API endpoints."""

from flask import Blueprint, jsonify, request

import database
from backend.security import (
    get_detection_config_dict,
    run_detection,
)

alerts_api = Blueprint(
    "alerts",
    __name__,
    url_prefix="/api/alerts",
)

VALID_SEVERITIES = {"Low", "Medium", "High"}
DEFAULT_LIMIT = 50
MAX_LIMIT = 500


@alerts_api.get("")
def list_alerts():
    """Return stored alerts, optionally filtered by severity and limit."""
    raw_severity = request.args.get("severity")
    raw_limit = request.args.get("limit")

    severity = None
    if raw_severity is not None:
        severity = raw_severity.strip().capitalize()

        if severity not in VALID_SEVERITIES:
            return jsonify({
                "error": "Invalid severity. Use Low, Medium, or High."
            }), 400

    if raw_limit is None:
        limit = DEFAULT_LIMIT
    else:
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid limit. Must be an integer."}), 400

        if not 1 <= limit <= MAX_LIMIT:
            return jsonify({
                "error": f"limit must be between 1 and {MAX_LIMIT}."
            }), 400

    database.init_db()

    alerts = database.get_alerts(
        limit=limit,
        severity=severity,
    )

    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
    })


@alerts_api.post("/scan")
def scan_alerts():
    """Run detection immediately and return alerts created by this scan."""
    database.init_db()

    alerts = run_detection()

    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
        "message": (
            "Detection scan completed. Alerts describe potentially "
            "suspicious activity, not confirmed attacks."
        ),
    })


@alerts_api.get("/config")
def alert_config():
    """Return the effective detection thresholds, excluding secrets."""
    return jsonify({
        "thresholds": get_detection_config_dict(),
        "valid_severities": sorted(VALID_SEVERITIES),
        "alert_limit": {
            "default": DEFAULT_LIMIT,
            "maximum": MAX_LIMIT,
        },
    })