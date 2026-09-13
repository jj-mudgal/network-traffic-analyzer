"""Unit tests for traffic statistics calculations (Sprint 3)."""
import pytest
import database
from database import get_statistics, insert_packet, init_db


@pytest.fixture
def test_db(monkeypatch, tmp_path):
    temp_db_path = tmp_path / "test_traffic_analyzer.db"
    monkeypatch.setattr(database, "DB_PATH", temp_db_path)
    init_db()
    yield temp_db_path


def test_total_packet_count_matches_stored_rows(test_db):
    insert_packet({"timestamp": "2026-08-30 10:00:01", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "source_port": 1000, "destination_port": 80, "protocol": "TCP", "packet_size": 100, "tcp_flags": "S"})
    insert_packet({"timestamp": "2026-08-30 10:00:02", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.3", "source_port": 2000, "destination_port": 53, "protocol": "UDP", "packet_size": 200, "tcp_flags": None})
    
    stats = get_statistics()
    assert stats["total"] == 2


def test_protocol_breakdown_counts_are_correct(test_db):
    insert_packet({"timestamp": "2026-08-30 10:00:01", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "source_port": 1000, "destination_port": 80, "protocol": "TCP", "packet_size": 100, "tcp_flags": "S"})
    insert_packet({"timestamp": "2026-08-30 10:00:02", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.3", "source_port": 2000, "destination_port": 53, "protocol": "UDP", "packet_size": 200, "tcp_flags": None})
    insert_packet({"timestamp": "2026-08-30 10:00:03", "source_ip": "10.0.0.4", "destination_ip": "10.0.0.1", "source_port": None, "destination_port": None, "protocol": "ICMP", "packet_size": 50, "tcp_flags": None})
    insert_packet({"timestamp": "2026-08-30 10:00:04", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.1", "source_port": None, "destination_port": None, "protocol": "TCP", "packet_size": 60, "tcp_flags": "A"})
    
    stats = get_statistics()
    assert stats["protocols"]["TCP"] == 2
    assert stats["protocols"]["UDP"] == 1
    assert stats["protocols"]["ICMP"] == 1


def test_statistics_with_empty_database_returns_zeroes(test_db):
    stats = get_statistics()
    assert stats["total"] == 0
    assert stats["protocols"] == {}


def test_statistics_ignore_malformed_protocol_values(test_db):
    insert_packet({"timestamp": "2026-08-30 10:00:01", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "source_port": 1000, "destination_port": 80, "protocol": "UNKNOWN_PROTO", "packet_size": 100, "tcp_flags": "S"})
    
    stats = get_statistics()
    assert stats["total"] == 1
    assert stats["protocols"]["UNKNOWN_PROTO"] == 1
