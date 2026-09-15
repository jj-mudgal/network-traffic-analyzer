"""
database.py — SQLite access layer for the Network Traffic Analyzer.

Schema follows Section 5 of docs/Architecture.md (packets table).
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "traffic_analyzer.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the packets table if it doesn't already exist."""
    conn = get_connection()
    conn.execute(
        """
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
    )
    conn.commit()
    conn.close()


def insert_packet(packet_data: dict):
    """Insert a single packet metadata record into the database."""
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO packets
            (timestamp, source_ip, destination_ip, source_port,
             destination_port, protocol, packet_size, tcp_flags)
        VALUES (:timestamp, :source_ip, :destination_ip, :source_port,
                :destination_port, :protocol, :packet_size, :tcp_flags)
        """,
        packet_data
    )
    conn.commit()
    conn.close()


def get_all_packets(limit=200):
    """Return the most recent `limit` packets, newest first."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_filtered_packets(limit=200, protocol=None, source_ip=None, destination_ip=None, source_port=None, destination_port=None):
    """Retrieve packets matching the optional filter criteria."""
    query = "SELECT * FROM packets WHERE 1=1"
    params = {}

    if protocol:
        query += " AND protocol = :protocol"
        params['protocol'] = protocol
    if source_ip:
        query += " AND source_ip = :source_ip"
        params['source_ip'] = source_ip
    if destination_ip:
        query += " AND destination_ip = :destination_ip"
        params['destination_ip'] = destination_ip
    if source_port is not None:
        query += " AND source_port = :source_port"
        params['source_port'] = source_port
    if destination_port is not None:
        query += " AND destination_port = :destination_port"
        params['destination_port'] = destination_port

    query += " ORDER BY id DESC LIMIT :limit"
    params['limit'] = limit

    conn = get_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_statistics():
    """Return aggregate traffic statistics from stored packet metadata."""
    conn = get_connection()

    total = conn.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]

    total_bytes = conn.execute(
        "SELECT COALESCE(SUM(packet_size), 0) FROM packets"
    ).fetchone()[0]

    average_packet_size = conn.execute(
        "SELECT COALESCE(AVG(packet_size), 0) FROM packets"
    ).fetchone()[0]

    protocol_rows = conn.execute(
        """
        SELECT protocol, COUNT(*) AS count
        FROM packets
        GROUP BY protocol
        ORDER BY count DESC
        """
    ).fetchall()

    protocol_byte_rows = conn.execute(
        """
        SELECT protocol, COALESCE(SUM(packet_size), 0) AS bytes
        FROM packets
        GROUP BY protocol
        ORDER BY bytes DESC
        """
    ).fetchall()

    source_port_rows = conn.execute(
        """
        SELECT source_port, COUNT(*) AS count
        FROM packets
        WHERE source_port IS NOT NULL
        GROUP BY source_port
        ORDER BY count DESC
        LIMIT 10
        """
    ).fetchall()

    destination_port_rows = conn.execute(
        """
        SELECT destination_port, COUNT(*) AS count
        FROM packets
        WHERE destination_port IS NOT NULL
        GROUP BY destination_port
        ORDER BY count DESC
        LIMIT 10
        """
    ).fetchall()

    source_ip_rows = conn.execute(
        """
        SELECT source_ip, COUNT(*) AS count
        FROM packets
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 10
        """
    ).fetchall()

    destination_ip_rows = conn.execute(
        """
        SELECT destination_ip, COUNT(*) AS count
        FROM packets
        GROUP BY destination_ip
        ORDER BY count DESC
        LIMIT 10
        """
    ).fetchall()

    traffic_pair_rows = conn.execute(
        """
        SELECT source_ip, destination_ip, COUNT(*) AS packets,
               COALESCE(SUM(packet_size), 0) AS bytes
        FROM packets
        GROUP BY source_ip, destination_ip
        ORDER BY packets DESC
        LIMIT 10
        """
    ).fetchall()

    port_activity_rows = conn.execute(
        """
        SELECT source_ip, COUNT(DISTINCT destination_port) AS unique_destination_ports
        FROM packets
        WHERE destination_port IS NOT NULL
        GROUP BY source_ip
        ORDER BY unique_destination_ports DESC
        LIMIT 10
        """
    ).fetchall()

    conn.close()

    return {
        "total": total,
        "total_bytes": total_bytes,
        "average_packet_size": round(average_packet_size, 2),
        "protocols": {
            row["protocol"]: row["count"]
            for row in protocol_rows
        },
        "protocol_bytes": {
            row["protocol"]: row["bytes"]
            for row in protocol_byte_rows
        },
        "source_ports": [
            {
                "port": row["source_port"],
                "count": row["count"],
            }
            for row in source_port_rows
        ],
        "destination_ports": [
            {
                "port": row["destination_port"],
                "count": row["count"],
            }
            for row in destination_port_rows
        ],
        "top_source_ips": [
            {
                "ip": row["source_ip"],
                "count": row["count"],
            }
            for row in source_ip_rows
        ],
        "top_destination_ips": [
            {
                "ip": row["destination_ip"],
                "count": row["count"],
            }
            for row in destination_ip_rows
        ],
        "traffic_pairs": [
            {
                "source_ip": row["source_ip"],
                "destination_ip": row["destination_ip"],
                "packets": row["packets"],
                "bytes": row["bytes"],
            }
            for row in traffic_pair_rows
        ],
        "port_activity": [
            {
                "source_ip": row["source_ip"],
                "unique_destination_ports": row["unique_destination_ports"],
            }
            for row in port_activity_rows
        ],
    }

def seed_sample_data():
    """
    Insert a handful of sample rows ONLY if the table is empty.
    Remove the call to this in app.py once real packet capture
    is feeding the database.
    """
    conn = get_connection()
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
    conn.close()
