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
