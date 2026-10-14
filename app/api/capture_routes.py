"""REST endpoints for packet capture control."""

from flask import Blueprint, jsonify, request

from backend.capture import (
    CaptureAlreadyRunningError,
    capture_status,
    list_interfaces,
    start_capture,
    stop_capture,
)

capture_api = Blueprint("capture_api", __name__, url_prefix="/api/capture")


@capture_api.get("/interfaces")
def interfaces():
    try:
        return jsonify({"interfaces": list_interfaces()})
    except Exception as exc:
        return jsonify({"interfaces": [], "error": str(exc)}), 500


@capture_api.get("/status")
def status():
    return jsonify(capture_status())


@capture_api.post("/start")
def start():
    payload = request.get_json(silent=True) or {}
    try:
        state = start_capture(payload.get("interface"))
    except CaptureAlreadyRunningError as exc:
        return jsonify({"error": str(exc), "status": capture_status()}), 409
    except ValueError as exc:
        return jsonify({"error": str(exc), "status": capture_status()}), 400
    except Exception as exc:
        return jsonify({"error": str(exc), "status": capture_status()}), 500
    return jsonify(state), 202


@capture_api.post("/stop")
def stop():
    return jsonify(stop_capture())
