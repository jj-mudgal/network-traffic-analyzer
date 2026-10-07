"""
database.py — SQLite access layer for the Network Traffic Analyzer.

Schema follows Section 5 of docs/architecture.md.
"""

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("DATABASE_PATH", Path(__file__).parent / "traffic_analyzer.db"))

PACKETS_SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT NOT NULL,
    packet_size INTEGER NOT NULL,
    tcp_flags TEXT
)
"""

# Extra tables / indexes registered by later sprints.
EXTRA_SCHEMA = []

_INSERT_PACKET_SQL = """
INSERT INTO packets
    (timestamp, source_ip, destination_ip, source_port,
     destination_port, protocol, packet_size, tcp_flags)
VALUES (:timestamp, :source_ip, :destination_ip, :source_port,
        :destination_port, :protocol, :packet_size, :tcp_flags)
"""


def get_connection():
    path = Path(DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the tables/indexes if they don't already exist."""
    conn = get_connection()
    try:
        conn.execute(PACKETS_SCHEMA)
        for statement in EXTRA_SCHEMA:
            conn.execute(statement)
        conn.commit()
    finally:
        conn.close()


def _normalize_timestamp(ts):
    """Epoch floats (from Scapy) become 'YYYY-MM-DD HH:MM:SS' UTC strings."""
    if ts is None:
        ts = datetime.now(timezone.utc).timestamp()
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return ts


def _prepare_packet(packet_data):
    data = dict(packet_data)
    data["timestamp"] = _normalize_timestamp(data.get("timestamp"))
    for key in ("source_port", "destination_port", "tcp_flags"):
        data.setdefault(key, None)
    return data


def insert_packet(packet_data: dict):
    """Insert a single packet metadata record into the database."""
    conn = get_connection()
    try:
        conn.execute(_INSERT_PACKET_SQL, _prepare_packet(packet_data))
        conn.commit()
    finally:
        conn.close()


def get_all_packets(limit=200):
    """Return the most recent `limit` packets, newest first."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def _build_conditions(protocol, source_ip, destination_ip, source_port, destination_port):
    """
    Shared by the packet list and the statistics queries so both always
    describe exactly the same rows. IPs match by substring, protocol and
    ports match exactly. Values are always bound parameters.
    """
    conditions, params = [], []
    if protocol:
        conditions.append("UPPER(protocol) = ?")
        params.append(protocol.upper())
    if source_ip:
        conditions.append("source_ip LIKE ?")
        params.append(f"%{source_ip}%")
    if destination_ip:
        conditions.append("destination_ip LIKE ?")
        params.append(f"%{destination_ip}%")
    if source_port is not None:
        conditions.append("source_port = ?")
        params.append(source_port)
    if destination_port is not None:
        conditions.append("destination_port = ?")
        params.append(destination_port)
    return conditions, params


def _where(conditions):
    return " WHERE " + " AND ".join(conditions) if conditions else ""


def get_filtered_packets(
    protocol=None,
    source_ip=None,
    destination_ip=None,
    source_port=None,
    destination_port=None,
    limit=200,
):
    """Return packets matching the given filters (AND-combined), newest first."""
    conditions, params = _build_conditions(
        protocol, source_ip, destination_ip, source_port, destination_port
    )
    query = f"SELECT * FROM packets{_where(conditions)} ORDER BY id DESC LIMIT ?"
    conn = get_connection()
    try:
        rows = conn.execute(query, params + [limit]).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def get_statistics(
    protocol=None,
    source_ip=None,
    destination_ip=None,
    source_port=None,
    destination_port=None,
):
    """
    Aggregate traffic statistics over the packets matching the filters
    (no filters = whole table). The f-strings below only interpolate
    WHERE clauses made of '?' placeholders; values are always bound.
    """
    conditions, params = _build_conditions(
        protocol, source_ip, destination_ip, source_port, destination_port
    )
    base = _where(conditions)
    with_src_port = _where(conditions + ["source_port IS NOT NULL"])
    with_dst_port = _where(conditions + ["destination_port IS NOT NULL"])

    conn = get_connection()
    try:
        def rows(sql):
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

        total, total_bytes = conn.execute(
            f"SELECT COUNT(*), COALESCE(SUM(packet_size), 0) FROM packets{base}", params
        ).fetchone()

        by_protocol = rows(
            "SELECT UPPER(protocol) AS name, COUNT(*) AS packets, "
            f"COALESCE(SUM(packet_size), 0) AS bytes FROM packets{base} "
            "GROUP BY UPPER(protocol)"
        )

        stats = {
            "total": total,
            "total_bytes": total_bytes,
            "average_packet_size": round(total_bytes / total, 2) if total else 0,
            "protocols": {r["name"]: r["packets"] for r in by_protocol},
            "protocol_bytes": {r["name"]: r["bytes"] for r in by_protocol},
            "source_ports": rows(
                f"SELECT source_port AS port, COUNT(*) AS packets FROM packets{with_src_port} "
                "GROUP BY source_port ORDER BY packets DESC, port LIMIT 10"
            ),
            "destination_ports": rows(
                f"SELECT destination_port AS port, COUNT(*) AS packets FROM packets{with_dst_port} "
                "GROUP BY destination_port ORDER BY packets DESC, port LIMIT 10"
            ),
            "top_source_ips": rows(
                "SELECT source_ip AS ip, COUNT(*) AS packets, "
                f"COALESCE(SUM(packet_size), 0) AS bytes FROM packets{base} "
                "GROUP BY source_ip ORDER BY packets DESC, ip LIMIT 10"
            ),
            "top_destination_ips": rows(
                "SELECT destination_ip AS ip, COUNT(*) AS packets, "
                f"COALESCE(SUM(packet_size), 0) AS bytes FROM packets{base} "
                "GROUP BY destination_ip ORDER BY packets DESC, ip LIMIT 10"
            ),
            "traffic_pairs": rows(
                "SELECT source_ip, destination_ip, COUNT(*) AS packets, "
                f"COALESCE(SUM(packet_size), 0) AS bytes FROM packets{base} "
                "GROUP BY source_ip, destination_ip "
                "ORDER BY packets DESC, bytes DESC LIMIT 10"
            ),
            "port_activity": rows(
                "SELECT source_ip, COUNT(DISTINCT destination_port) AS unique_destination_ports, "
                f"COUNT(*) AS packets FROM packets{with_dst_port} "
                "GROUP BY source_ip "
                "ORDER BY unique_destination_ports DESC, packets DESC LIMIT 10"
            ),
        }
    finally:
        conn.close()
    return stats


def seed_sample_data():
    """Insert a few sample rows ONLY if the table is empty (python run.py --seed)."""
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        if count == 0:
            sample_rows = [
                ("2026-08-30 10:00:01", "192.168.1.10", "142.250.66.14", 51423, 443, "TCP", 1500, "ACK"),
                ("2026-08-30 10:00:02", "192.168.1.10", "8.8.8.8", 51424, 53, "UDP", 72, None),
                ("2026-08-30 10:00:03", "192.168.1.15", "192.168.1.1", None, None, "ICMP", 98, None),
                ("2026-08-30 10:00:04", "192.168.1.10", "13.107.42.14", 51425, 443, "TCP", 850, "SYN"),
                ("2026-08-30 10:00:05", "192.168.1.12", "192.168.1.10", 22, 51500, "TCP", 64, "FIN"),
                ("2026-08-30 10:00:06", "192.168.1.18", "192.168.1.255", None, 137, "UDP", 92, None),
            ]
            conn.executemany(
                """
                INSERT INTO packets
                    (timestamp, source_ip, destination_ip, source_port,
                     destination_port, protocol, packet_size, tcp_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                sample_rows,
            )
            conn.commit()
    finally:
        conn.close()
