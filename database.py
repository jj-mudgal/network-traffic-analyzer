"""
database.py — SQLite access layer for the Network Traffic Analyzer.

Schema follows Section 5 of docs/architecture.md.
"""

import os
import sqlite3
from datetime import datetime, timezone, timedelta
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

SECURITY_ALERTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL
)
"""

INDEXES_SCHEMA = [
    "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_packets_source_ip ON packets(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_packets_destination_ip ON packets(destination_ip)",
    "CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol)",
    "CREATE INDEX IF NOT EXISTS idx_packets_destination_port ON packets(destination_port)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON security_alerts(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_type ON security_alerts(alert_type)",
]

# Extra tables / indexes registered by later sprints.
EXTRA_SCHEMA = [SECURITY_ALERTS_SCHEMA] + INDEXES_SCHEMA

_INSERT_PACKET_SQL = """
INSERT INTO packets
    (timestamp, source_ip, destination_ip, source_port,
     destination_port, protocol, packet_size, tcp_flags)
VALUES (:timestamp, :source_ip, :destination_ip, :source_port,
        :destination_port, :protocol, :packet_size, :tcp_flags)
"""

_INSERT_ALERT_SQL = """
INSERT INTO security_alerts
    (timestamp, source_ip, alert_type, severity, description)
VALUES (:timestamp, :source_ip, :alert_type, :severity, :description)
"""

VALID_SEVERITIES = {"Low", "Medium", "High"}


def get_connection():
    path = Path(DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.DatabaseError:
        pass
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


def insert_packets(packets: list) -> int:
    """Insert multiple packet metadata records into the database in a single transaction.

    Returns the number of packets inserted.
    """
    if not packets:
        return 0
    prepared = [_prepare_packet(p) for p in packets]
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.executemany(_INSERT_PACKET_SQL, prepared)
        conn.commit()
        return len(prepared)
    finally:
        conn.close()


def prune_packets(max_rows: int) -> int:
    """Keep at most `max_rows` newest packets, deleting older ones.

    Returns the number of rows deleted.
    """
    if max_rows is None:
        return 0
    conn = get_connection()
    try:
        if max_rows <= 0:
            cursor = conn.execute("DELETE FROM packets")
            deleted = cursor.rowcount
            conn.commit()
            return deleted

        cursor = conn.execute(
            """
            DELETE FROM packets
            WHERE id NOT IN (
                SELECT id FROM packets ORDER BY id DESC LIMIT ?
            )
            """,
            (max_rows,),
        )
        deleted = cursor.rowcount
        conn.commit()
        return deleted
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


def _normalize_severity(severity: str) -> str:
    if not severity or not isinstance(severity, str):
        raise ValueError(f"Invalid severity: {severity!r}. Expected one of {sorted(VALID_SEVERITIES)}")
    normalized = severity.strip().capitalize()
    if normalized not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity!r}. Expected one of {sorted(VALID_SEVERITIES)}")
    return normalized


def insert_alert(alert_data: dict) -> int:
    """Insert a single security alert into the database.

    Validates severity ('Low', 'Medium', 'High') and required fields.
    Returns the ID of the inserted alert row.
    """
    if not isinstance(alert_data, dict):
        raise ValueError("alert_data must be a dictionary")

    data = dict(alert_data)
    data["timestamp"] = _normalize_timestamp(data.get("timestamp"))
    data["severity"] = _normalize_severity(data.get("severity"))

    source_ip = data.get("source_ip")
    if not source_ip or not isinstance(source_ip, str):
        raise ValueError("source_ip must be a non-empty string")

    alert_type = data.get("alert_type")
    if not alert_type or not isinstance(alert_type, str):
        raise ValueError("alert_type must be a non-empty string")

    description = data.get("description")
    if not description or not isinstance(description, str):
        raise ValueError("description must be a non-empty string")

    conn = get_connection()
    try:
        cursor = conn.execute(_INSERT_ALERT_SQL, data)
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_alerts(limit=50, severity=None) -> list:
    """Return the most recent `limit` alerts, newest first.

    Optionally filter by severity ('Low', 'Medium', 'High').
    """
    if limit is None or limit < 0:
        limit = 50
    conditions = []
    params = []
    if severity is not None:
        normalized_sev = _normalize_severity(severity)
        conditions.append("severity = ?")
        params.append(normalized_sev)

    where_clause = _where(conditions)
    query = f"SELECT * FROM security_alerts{where_clause} ORDER BY id DESC LIMIT ?"
    params.append(limit)

    conn = get_connection()
    try:
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def _compute_cutoff(window_seconds, now=None) -> str:
    if now is None:
        ref_time = datetime.now(timezone.utc)
    elif isinstance(now, (int, float)):
        ref_time = datetime.fromtimestamp(now, tz=timezone.utc)
    elif isinstance(now, str):
        ref_str = now.replace("Z", "+00:00")
        try:
            ref_time = datetime.fromisoformat(ref_str)
        except ValueError:
            ref_time = datetime.strptime(now, "%Y-%m-%d %H:%M:%S")
        if ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)
    elif isinstance(now, datetime):
        ref_time = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    else:
        ref_time = datetime.now(timezone.utc)

    cutoff = ref_time - timedelta(seconds=window_seconds)
    return cutoff.strftime("%Y-%m-%d %H:%M:%S")


def has_recent_alert(alert_type: str, source_ip: str, window_seconds: int, now=None) -> bool:
    """Return True if an alert of `alert_type` for `source_ip` occurred within `window_seconds`.

    `window_seconds` is measured back from `now` (default: current UTC time).
    """
    if window_seconds is None or window_seconds < 0:
        return False

    cutoff_str = _compute_cutoff(window_seconds, now=now)
    query = """
    SELECT 1 FROM security_alerts
    WHERE alert_type = ? AND source_ip = ? AND timestamp >= ?
    LIMIT 1
    """
    conn = get_connection()
    try:
        row = conn.execute(query, (alert_type, source_ip, cutoff_str)).fetchone()
    finally:
        conn.close()
    return row is not None


def get_port_scan_candidates(window_seconds: int, port_threshold: int = 10, now=None) -> list:
    """Return source IPs that contacted at least `port_threshold` distinct destination ports
    within `window_seconds`.

    Returns list of dicts: [{'source_ip': str, 'unique_ports': int, 'port_count': int, 'packet_count': int}]
    ordered by unique_ports DESC, packet_count DESC.
    """
    cutoff_str = _compute_cutoff(window_seconds, now=now)
    query = """
    SELECT source_ip,
           COUNT(DISTINCT destination_port) AS unique_ports,
           COUNT(*) AS packet_count
    FROM packets
    WHERE timestamp >= ? AND destination_port IS NOT NULL AND source_ip IS NOT NULL AND source_ip != ''
    GROUP BY source_ip
    HAVING COUNT(DISTINCT destination_port) >= ?
    ORDER BY unique_ports DESC, packet_count DESC
    """
    conn = get_connection()
    try:
        rows = conn.execute(query, (cutoff_str, port_threshold)).fetchall()
    finally:
        conn.close()

    return [
        {
            "source_ip": r["source_ip"],
            "unique_ports": r["unique_ports"],
            "port_count": r["unique_ports"],
            "packet_count": r["packet_count"],
        }
        for r in rows
    ]


def get_source_packet_counts(window_seconds: int, threshold: int = 1, now=None) -> list:
    """Return source IPs that sent at least `threshold` packets within `window_seconds`.

    Returns list of dicts: [{'source_ip': str, 'packet_count': int, 'count': int}]
    ordered by packet_count DESC.
    """
    cutoff_str = _compute_cutoff(window_seconds, now=now)
    query = """
    SELECT source_ip, COUNT(*) AS packet_count
    FROM packets
    WHERE timestamp >= ? AND source_ip IS NOT NULL AND source_ip != ''
    GROUP BY source_ip
    HAVING COUNT(*) >= ?
    ORDER BY packet_count DESC
    """
    conn = get_connection()
    try:
        rows = conn.execute(query, (cutoff_str, threshold)).fetchall()
    finally:
        conn.close()

    return [
        {
            "source_ip": r["source_ip"],
            "packet_count": r["packet_count"],
            "count": r["packet_count"],
        }
        for r in rows
    ]

