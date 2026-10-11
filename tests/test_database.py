"""Unit tests for SQLite database operations (packets table)."""
import pytest
import sqlite3
import database

@pytest.fixture
def test_db(monkeypatch, tmp_path):
    # Use a temporary database file for isolated testing
    temp_db_path = tmp_path / "test_traffic_analyzer.db"
    monkeypatch.setattr(database, "DB_PATH", temp_db_path)
    
    # Initialize the database and ensure the table exists
    database.init_db()
    
    yield temp_db_path
    
    # Clean up is handled by pytest's tmp_path

def test_init_db_creates_packets_table(test_db):
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='packets'")
    table = cursor.fetchone()
    conn.close()
    
    assert table is not None
    assert table[0] == 'packets'

def test_insert_packet_stores_metadata_correctly(test_db):
    packet_data = {
        "timestamp": "2026-08-30 12:00:00",
        "source_ip": "192.168.1.10",
        "destination_ip": "1.1.1.1",
        "source_port": 12345,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_size": 1024,
        "tcp_flags": "SYN"
    }
    
    database.insert_packet(packet_data)
    
    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM packets").fetchone()
    conn.close()
    
    assert row is not None
    assert row["source_ip"] == "192.168.1.10"
    assert row["protocol"] == "TCP"

def test_get_all_packets_returns_expected_rows(test_db):
    packet_data_1 = {
        "timestamp": "2026-08-30 12:00:00",
        "source_ip": "192.168.1.10",
        "destination_ip": "1.1.1.1",
        "source_port": 12345,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_size": 1024,
        "tcp_flags": "SYN"
    }
    packet_data_2 = {
        "timestamp": "2026-08-30 12:00:01",
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "source_port": 12346,
        "destination_port": 53,
        "protocol": "UDP",
        "packet_size": 64,
        "tcp_flags": None
    }
    
    database.insert_packet(packet_data_1)
    database.insert_packet(packet_data_2)
    
    packets = database.get_all_packets(limit=10)
    
    assert len(packets) == 2
    # Newest should be first because get_all_packets orders by id DESC
    assert packets[0]["protocol"] == "UDP"
    assert packets[1]["protocol"] == "TCP"

def test_insert_tcp_packet_stores_flags_and_ports(test_db):
    packet_data = {
        "timestamp": "2026-08-30 12:00:00",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_port": 80,
        "protocol": "TCP",
        "packet_size": 512,
        "tcp_flags": "SYN,ACK",
    }
    database.insert_packet(packet_data)

    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM packets WHERE protocol = 'TCP'").fetchone()
    conn.close()

    assert row is not None
    assert row["source_port"] == 54321
    assert row["destination_port"] == 80
    assert row["tcp_flags"] == "SYN,ACK"
    assert row["protocol"] == "TCP"


def test_insert_udp_packet_stores_ports_no_flags(test_db):
    packet_data = {
        "timestamp": "2026-08-30 12:00:01",
        "source_ip": "192.168.1.20",
        "destination_ip": "8.8.8.8",
        "source_port": 5353,
        "destination_port": 53,
        "protocol": "UDP",
        "packet_size": 128,
        "tcp_flags": None,
    }
    database.insert_packet(packet_data)

    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM packets WHERE protocol = 'UDP'").fetchone()
    conn.close()

    assert row is not None
    assert row["source_port"] == 5353
    assert row["destination_port"] == 53
    assert row["tcp_flags"] is None
    assert row["protocol"] == "UDP"


def test_insert_icmp_packet_stores_without_ports_or_flags(test_db):
    packet_data = {
        "timestamp": "2026-08-30 12:00:02",
        "source_ip": "192.168.1.30",
        "destination_ip": "192.168.1.1",
        "source_port": None,
        "destination_port": None,
        "protocol": "ICMP",
        "packet_size": 64,
        "tcp_flags": None,
    }
    database.insert_packet(packet_data)

    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM packets WHERE protocol = 'ICMP'").fetchone()
    conn.close()

    assert row is not None
    assert row["source_port"] is None
    assert row["destination_port"] is None
    assert row["tcp_flags"] is None
    assert row["protocol"] == "ICMP"


def test_get_all_packets_returns_mixed_protocol_rows(test_db):
    packets = [
        {
            "timestamp": "2026-08-30 12:00:00",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.1",
            "source_port": 1000,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_size": 200,
            "tcp_flags": "ACK",
        },
        {
            "timestamp": "2026-08-30 12:00:01",
            "source_ip": "192.168.1.20",
            "destination_ip": "8.8.8.8",
            "source_port": 2000,
            "destination_port": 53,
            "protocol": "UDP",
            "packet_size": 100,
            "tcp_flags": None,
        },
        {
            "timestamp": "2026-08-30 12:00:02",
            "source_ip": "192.168.1.30",
            "destination_ip": "192.168.1.1",
            "source_port": None,
            "destination_port": None,
            "protocol": "ICMP",
            "packet_size": 50,
            "tcp_flags": None,
        },
    ]
    for p in packets:
        database.insert_packet(p)

    retrieved = database.get_all_packets(limit=10)
    assert len(retrieved) == 3
    protocols = {r["protocol"] for r in retrieved}
    assert protocols == {"TCP", "UDP", "ICMP"}

