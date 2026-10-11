"""Unit tests for alerts database operations, WAL mode, bulk insert, pruning, and detection queries."""
import sqlite3
import pytest
from datetime import datetime, timezone, timedelta

import database


@pytest.fixture
def alert_db(monkeypatch, tmp_path):
    """Temporary file database initialized with packets and security_alerts tables."""
    temp_db_path = tmp_path / "test_alerts.db"
    monkeypatch.setattr(database, "DB_PATH", temp_db_path)
    database.init_db()
    yield temp_db_path


def test_init_db_creates_security_alerts_table_and_indexes(alert_db):
    conn = sqlite3.connect(alert_db)
    cursor = conn.cursor()

    # Verify security_alerts table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_alerts'")
    table = cursor.fetchone()
    assert table is not None
    assert table[0] == "security_alerts"

    # Verify indexes exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
    indexes = {row[0] for row in cursor.fetchall()}
    conn.close()

    expected_indexes = {
        "idx_packets_timestamp",
        "idx_packets_source_ip",
        "idx_packets_destination_ip",
        "idx_packets_protocol",
        "idx_packets_destination_port",
        "idx_alerts_timestamp",
        "idx_alerts_source_ip",
    }
    for idx in expected_indexes:
        assert idx in indexes, f"Expected index {idx} not found in {indexes}"


def test_wal_mode_enabled(alert_db):
    conn = database.get_connection()
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
    finally:
        conn.close()


def test_insert_packets_bulk(alert_db):
    packets = [
        {
            "timestamp": "2026-10-11 10:00:01",
            "source_ip": f"192.168.1.{i}",
            "destination_ip": "10.0.0.1",
            "source_port": 1000 + i,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_size": 100 + i,
            "tcp_flags": "SYN",
        }
        for i in range(5)
    ]
    inserted = database.insert_packets(packets)
    assert inserted == 5

    stored = database.get_all_packets(limit=10)
    assert len(stored) == 5
    # Order is newest first
    assert stored[0]["source_ip"] == "192.168.1.4"
    assert stored[4]["source_ip"] == "192.168.1.0"


def test_insert_packets_empty_list(alert_db):
    inserted = database.insert_packets([])
    assert inserted == 0
    assert len(database.get_all_packets()) == 0


def test_prune_packets_removes_oldest(alert_db):
    packets = [
        {
            "timestamp": f"2026-10-11 10:00:0{i}",
            "source_ip": f"10.0.0.{i}",
            "destination_ip": "8.8.8.8",
            "source_port": 1000 + i,
            "destination_port": 53,
            "protocol": "UDP",
            "packet_size": 50,
            "tcp_flags": None,
        }
        for i in range(10)
    ]
    database.insert_packets(packets)

    # Prune to keep only 6 packets
    deleted = database.prune_packets(max_rows=6)
    assert deleted == 4

    remaining = database.get_all_packets(limit=20)
    assert len(remaining) == 6
    # The remaining 6 should be the latest (IDs 5 to 9, so 10.0.0.4 to 10.0.0.9)
    remaining_ips = {r["source_ip"] for r in remaining}
    assert "10.0.0.0" not in remaining_ips
    assert "10.0.0.1" not in remaining_ips
    assert "10.0.0.2" not in remaining_ips
    assert "10.0.0.3" not in remaining_ips
    assert "10.0.0.9" in remaining_ips


def test_prune_packets_under_limit(alert_db):
    packets = [
        {
            "timestamp": "2026-10-11 10:00:01",
            "source_ip": "10.0.0.1",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "packet_size": 50,
        }
    ]
    database.insert_packets(packets)

    deleted = database.prune_packets(max_rows=5)
    assert deleted == 0
    assert len(database.get_all_packets()) == 1


def test_prune_packets_zero_or_negative(alert_db):
    packets = [
        {
            "timestamp": f"2026-10-11 10:00:0{i}",
            "source_ip": "10.0.0.1",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "packet_size": 50,
        }
        for i in range(3)
    ]
    database.insert_packets(packets)

    deleted = database.prune_packets(max_rows=0)
    assert deleted == 3
    assert len(database.get_all_packets()) == 0


def test_insert_alert_valid_and_normalization(alert_db):
    alert_1 = {
        "timestamp": "2026-10-11 10:00:00",
        "source_ip": "192.168.1.100",
        "alert_type": "Possible Port Scan",
        "severity": "low",
        "description": "Scanned multiple ports",
    }
    alert_2 = {
        "timestamp": "2026-10-11 10:00:01",
        "source_ip": "192.168.1.101",
        "alert_type": "Abnormal Traffic",
        "severity": "MEDIUM",
        "description": "High packet volume",
    }
    alert_3 = {
        "timestamp": "2026-10-11 10:00:02",
        "source_ip": "192.168.1.102",
        "alert_type": "Possible Port Scan",
        "severity": "High",
        "description": "Scanned critical ports",
    }

    id1 = database.insert_alert(alert_1)
    id2 = database.insert_alert(alert_2)
    id3 = database.insert_alert(alert_3)

    assert id1 > 0 and id2 > id1 and id3 > id2

    alerts = database.get_alerts(limit=10)
    assert len(alerts) == 3
    # Newest first
    assert alerts[0]["severity"] == "High"
    assert alerts[1]["severity"] == "Medium"
    assert alerts[2]["severity"] == "Low"


def test_insert_alert_invalid_severity(alert_db):
    invalid_alert = {
        "timestamp": "2026-10-11 10:00:00",
        "source_ip": "192.168.1.100",
        "alert_type": "Possible Port Scan",
        "severity": "Critical",
        "description": "Severe attack",
    }
    with pytest.raises(ValueError, match="Invalid severity"):
        database.insert_alert(invalid_alert)

    invalid_alert["severity"] = ""
    with pytest.raises(ValueError, match="Invalid severity"):
        database.insert_alert(invalid_alert)

    invalid_alert["severity"] = None
    with pytest.raises(ValueError, match="Invalid severity"):
        database.insert_alert(invalid_alert)


def test_insert_alert_missing_required_fields(alert_db):
    base = {
        "timestamp": "2026-10-11 10:00:00",
        "source_ip": "192.168.1.100",
        "alert_type": "Possible Port Scan",
        "severity": "Medium",
        "description": "Test alert",
    }

    # Missing source_ip
    bad1 = dict(base, source_ip="")
    with pytest.raises(ValueError, match="source_ip"):
        database.insert_alert(bad1)

    # Missing alert_type
    bad2 = dict(base, alert_type="")
    with pytest.raises(ValueError, match="alert_type"):
        database.insert_alert(bad2)

    # Missing description
    bad3 = dict(base, description="")
    with pytest.raises(ValueError, match="description"):
        database.insert_alert(bad3)


def test_get_alerts_limits_and_filtering(alert_db):
    for i in range(6):
        database.insert_alert({
            "timestamp": f"2026-10-11 10:00:0{i}",
            "source_ip": f"192.168.1.{i}",
            "alert_type": "Possible Port Scan",
            "severity": "High" if i % 2 == 0 else "Low",
            "description": f"Alert {i}",
        })

    # Limit = 3
    recent = database.get_alerts(limit=3)
    assert len(recent) == 3
    assert recent[0]["description"] == "Alert 5"

    # Filter by High
    high_alerts = database.get_alerts(limit=10, severity="high")
    assert len(high_alerts) == 3
    assert all(a["severity"] == "High" for a in high_alerts)

    # Filter by Low
    low_alerts = database.get_alerts(limit=10, severity="LOW")
    assert len(low_alerts) == 3
    assert all(a["severity"] == "Low" for a in low_alerts)


def test_has_recent_alert_window(alert_db):
    ref_time = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    ts_alert = (ref_time - timedelta(seconds=20)).strftime("%Y-%m-%d %H:%M:%S")

    database.insert_alert({
        "timestamp": ts_alert,
        "source_ip": "192.168.1.50",
        "alert_type": "Possible Port Scan",
        "severity": "Medium",
        "description": "Port scan detected",
    })

    # Inside 30-second window
    assert database.has_recent_alert("Possible Port Scan", "192.168.1.50", window_seconds=30, now=ref_time) is True

    # Outside 10-second window
    assert database.has_recent_alert("Possible Port Scan", "192.168.1.50", window_seconds=10, now=ref_time) is False

    # Different alert type
    assert database.has_recent_alert("Abnormal Traffic", "192.168.1.50", window_seconds=30, now=ref_time) is False

    # Different source IP
    assert database.has_recent_alert("Possible Port Scan", "192.168.1.99", window_seconds=30, now=ref_time) is False


def test_get_port_scan_candidates(alert_db):
    ref_time = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    in_window_ts = (ref_time - timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S")
    out_window_ts = (ref_time - timedelta(seconds=90)).strftime("%Y-%m-%d %H:%M:%S")

    packets = []
    # Attacker 1: 5 distinct ports in window
    for port in range(1, 6):
        packets.append({
            "timestamp": in_window_ts,
            "source_ip": "10.0.0.99",
            "destination_ip": "192.168.1.1",
            "source_port": 12345,
            "destination_port": port,
            "protocol": "TCP",
            "packet_size": 60,
        })

    # Attacker 2: only 2 distinct ports in window (below threshold 4)
    for port in range(1, 3):
        packets.append({
            "timestamp": in_window_ts,
            "source_ip": "10.0.0.88",
            "destination_ip": "192.168.1.1",
            "source_port": 12345,
            "destination_port": port,
            "protocol": "TCP",
            "packet_size": 60,
        })

    # Attacker 3: 10 distinct ports, but OUTSIDE window
    for port in range(1, 11):
        packets.append({
            "timestamp": out_window_ts,
            "source_ip": "10.0.0.77",
            "destination_ip": "192.168.1.1",
            "source_port": 12345,
            "destination_port": port,
            "protocol": "TCP",
            "packet_size": 60,
        })

    database.insert_packets(packets)

    candidates = database.get_port_scan_candidates(window_seconds=30, port_threshold=4, now=ref_time)
    assert len(candidates) == 1
    assert candidates[0]["source_ip"] == "10.0.0.99"
    assert candidates[0]["unique_ports"] == 5
    assert candidates[0]["port_count"] == 5


def test_get_source_packet_counts(alert_db):
    ref_time = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    in_window_ts = (ref_time - timedelta(seconds=10)).strftime("%Y-%m-%d %H:%M:%S")
    out_window_ts = (ref_time - timedelta(seconds=100)).strftime("%Y-%m-%d %H:%M:%S")

    packets = []
    # Flooder 1: 15 packets in window
    for _ in range(15):
        packets.append({
            "timestamp": in_window_ts,
            "source_ip": "10.0.0.55",
            "destination_ip": "192.168.1.1",
            "protocol": "UDP",
            "packet_size": 1000,
        })

    # Regular host: 3 packets in window
    for _ in range(3):
        packets.append({
            "timestamp": in_window_ts,
            "source_ip": "10.0.0.44",
            "destination_ip": "192.168.1.1",
            "protocol": "UDP",
            "packet_size": 100,
        })

    # Old host: 20 packets, outside window
    for _ in range(20):
        packets.append({
            "timestamp": out_window_ts,
            "source_ip": "10.0.0.33",
            "destination_ip": "192.168.1.1",
            "protocol": "UDP",
            "packet_size": 100,
        })

    database.insert_packets(packets)

    counts = database.get_source_packet_counts(window_seconds=30, threshold=10, now=ref_time)
    assert len(counts) == 1
    assert counts[0]["source_ip"] == "10.0.0.55"
    assert counts[0]["packet_count"] == 15
    assert counts[0]["count"] == 15


def test_bound_parameters_prevent_sql_injection(alert_db):
    payload = "'; DROP TABLE packets; --"
    alert = {
        "timestamp": "2026-10-11 12:00:00",
        "source_ip": payload,
        "alert_type": "Possible Port Scan",
        "severity": "Low",
        "description": "SQLi test",
    }
    database.insert_alert(alert)

    # Check that packets table still exists
    conn = database.get_connection()
    try:
        table = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='packets'").fetchone()
        assert table is not None
    finally:
        conn.close()

    # Query with payload
    assert database.has_recent_alert("Possible Port Scan", payload, window_seconds=10000, now="2026-10-11 12:00:01") is True
