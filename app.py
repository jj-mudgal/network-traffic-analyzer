"""
app.py — Flask entry point for the Network Traffic Analyzer dashboard.

Routes:
    GET /              -> renders the dashboard page
    GET /api/packets   -> JSON list of packets (accepts filters)
    GET /api/stats     -> JSON protocol counts (respects same filters)
"""

from flask import Flask, jsonify, render_template, request

from database import init_db, get_all_packets, get_filtered_packets, seed_sample_data

app = Flask(__name__)


def _parse_filters():
    """
    Read filter query params from the request (?protocol=TCP&source_ip=...).
    Ports are validated as integers; an invalid port is treated as "no filter"
    rather than crashing the request.
    """
    protocol = request.args.get("protocol") or None
    source_ip = request.args.get("source_ip") or None
    destination_ip = request.args.get("destination_ip") or None

    source_port = request.args.get("source_port") or None
    destination_port = request.args.get("destination_port") or None
    try:
        source_port = int(source_port) if source_port else None
    except ValueError:
        source_port = None
    try:
        destination_port = int(destination_port) if destination_port else None
    except ValueError:
        destination_port = None

    return {
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
    }


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/packets")
def api_packets():
    filters = _parse_filters()
    return jsonify(get_filtered_packets(limit=200, **filters))


@app.route("/api/stats")
def api_stats():
    # Stats reflect the SAME filters as the table, so the cards and chart
    # always describe exactly what's currently shown, not the whole dataset.
    filters = _parse_filters()
    packets = get_filtered_packets(limit=10000, **filters)
    stats = {"total": len(packets), "TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
    for packet in packets:
        protocol = (packet.get("protocol") or "").upper()
        if protocol in ("TCP", "UDP", "ICMP"):
            stats[protocol] += 1
        else:
            stats["OTHER"] += 1
    return jsonify(stats)


if __name__ == "__main__":
    init_db()
    seed_sample_data()  # TODO: remove once packet capture module feeds real data
    app.run(debug=True, host="0.0.0.0", port=5000)
