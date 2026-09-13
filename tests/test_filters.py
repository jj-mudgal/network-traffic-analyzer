"""Unit tests for packet filtering (Sprint 3): protocol, IP, and port."""
import pytest
import database
from database import get_filtered_packets, insert_packet, init_db


@pytest.fixture
def test_db(monkeypatch, tmp_path):
    temp_db_path = tmp_path / "test_traffic_analyzer.db"
    monkeypatch.setattr(database, "DB_PATH", temp_db_path)
    init_db()
    
    # Insert some mixed packets for filtering tests
    insert_packet({"timestamp": "2026-08-30 10:00:01", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "source_port": 1000, "destination_port": 80, "protocol": "TCP", "packet_size": 100, "tcp_flags": "S"})
    insert_packet({"timestamp": "2026-08-30 10:00:02", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.3", "source_port": 2000, "destination_port": 53, "protocol": "UDP", "packet_size": 200, "tcp_flags": None})
    insert_packet({"timestamp": "2026-08-30 10:00:03", "source_ip": "10.0.0.4", "destination_ip": "10.0.0.1", "source_port": None, "destination_port": None, "protocol": "ICMP", "packet_size": 50, "tcp_flags": None})
    
    yield temp_db_path


def test_filter_by_protocol_returns_only_matching_packets(test_db):
    results = get_filtered_packets(protocol="TCP")
    assert len(results) == 1
    assert results[0]["protocol"] == "TCP"

    results_udp = get_filtered_packets(protocol="UDP")
    assert len(results_udp) == 1
    assert results_udp[0]["protocol"] == "UDP"


def test_filter_by_source_ip_returns_matching_packets(test_db):
    results = get_filtered_packets(source_ip="10.0.0.1")
    assert len(results) == 2
    for r in results:
        assert r["source_ip"] == "10.0.0.1"


def test_filter_by_destination_ip_returns_matching_packets(test_db):
    results = get_filtered_packets(destination_ip="10.0.0.1")
    assert len(results) == 1
    assert results[0]["destination_ip"] == "10.0.0.1"


def test_filter_by_source_port_returns_matching_packets(test_db):
    results = get_filtered_packets(source_port=1000)
    assert len(results) == 1
    assert results[0]["source_port"] == 1000


def test_filter_by_destination_port_returns_matching_packets(test_db):
    results = get_filtered_packets(destination_port=53)
    assert len(results) == 1
    assert results[0]["destination_port"] == 53


def test_combined_filters_apply_all_conditions(test_db):
    results = get_filtered_packets(source_ip="10.0.0.1", protocol="UDP")
    assert len(results) == 1
    assert results[0]["protocol"] == "UDP"
    assert results[0]["source_ip"] == "10.0.0.1"


def test_invalid_filter_input_handled_safely(test_db):
    results = get_filtered_packets(protocol="UNKNOWN")
    assert len(results) == 0


def test_no_filters_returns_existing_behavior(test_db):
    results = get_filtered_packets()
    assert len(results) == 3
