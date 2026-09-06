"""
app.py — Flask entry point for the Network Traffic Analyzer dashboard.

Sprint 1, Issue 5: "Create Initial Dashboard and Packet Display"
"""

from flask import Flask, jsonify, render_template

from database import init_db, get_all_packets, seed_sample_data

app = Flask(__name__)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/packets")
def api_packets():
    return jsonify(get_all_packets())


@app.route("/api/stats")
def api_stats():
    packets = get_all_packets(limit=10000)
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
    app.run(debug=True, port=5000)
