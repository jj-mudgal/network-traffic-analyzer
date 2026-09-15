"""Unit and API tests for packet filtering (Sprint 3)."""

import pytest

import database
from database import get_filtered_packets, insert_packet, init_db


@pytest.fixture
def test_db(monkeypatch, tmp_path):
    """Create a temporary database populated with test packets."""
    temp_db_path = tmp_path / "test_traffic_analyzer.db"
    monkeypatch.setattr(database, "DB_PATH", temp_db_path)

    init_db()

    insert_packet({
        "timestamp": 1000.0,
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "source_port": 1000,
        "destination_port": 80,
        "protocol": "TCP",
        "packet_size": 100,
        "tcp_flags": "S",
    })

    insert_packet({
        "timestamp": 1001.0,
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.3",
        "source_port": 2000,
        "destination_port": 53,
        "protocol": "UDP",
        "packet_size": 80,
        "tcp_flags": None,
    })

    insert_packet({
        "timestamp": 1002.0,
        "source_ip": "10.0.0.4",
        "destination_ip": "10.0.0.1",
        "source_port": None,
        "destination_port": None,
        "protocol": "ICMP",
        "packet_size": 64,
        "tcp_flags": None,
    })

    yield temp_db_path


# ---------------------------------------------------------------------------
# Database filtering tests
# ---------------------------------------------------------------------------

def test_filter_by_protocol_returns_only_matching_packets(test_db):
    results = get_filtered_packets(protocol="TCP")

    assert len(results) == 1
    assert results[0]["protocol"] == "TCP"


def test_filter_by_source_ip_returns_matching_packets(test_db):
    results = get_filtered_packets(source_ip="10.0.0.1")

    assert len(results) == 2

    for packet in results:
        assert packet["source_ip"] == "10.0.0.1"


def test_filter_by_destination_ip_returns_matching_packets(test_db):
    results = get_filtered_packets(destination_ip="10.0.0.1")

    assert len(results) == 1
    assert results[0]["destination_ip"] == "10.0.0.1"


def test_filter_by_source_port_returns_matching_packets(test_db):
    results = get_filtered_packets(source_port=2000)

    assert len(results) == 1
    assert results[0]["source_port"] == 2000


def test_filter_by_destination_port_returns_matching_packets(test_db):
    results = get_filtered_packets(destination_port=53)

    assert len(results) == 1
    assert results[0]["destination_port"] == 53


def test_combined_filters_apply_all_conditions(test_db):
    results = get_filtered_packets(
        source_ip="10.0.0.1",
        protocol="UDP",
    )

    assert len(results) == 1
    assert results[0]["protocol"] == "UDP"
    assert results[0]["source_ip"] == "10.0.0.1"


def test_invalid_filter_input_handled_safely(test_db):
    results = get_filtered_packets(protocol="UNKNOWN")

    assert len(results) == 0


def test_no_filters_returns_existing_behavior(test_db):
    results = get_filtered_packets()

    assert len(results) == 3


# ---------------------------------------------------------------------------
# Flask API filtering tests
# ---------------------------------------------------------------------------

def test_api_protocol_filter(test_db):
    from app.app import create_app

    app = create_app()
    client = app.test_client()

    response = client.get("/api/packets?protocol=TCP")

    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == 1
    assert data["packets"][0]["protocol"] == "TCP"


def test_api_ip_filter(test_db):
    from app.app import create_app

    app = create_app()
    client = app.test_client()

    response = client.get("/api/packets?source_ip=10.0.0.1")

    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == 2

    for packet in data["packets"]:
        assert packet["source_ip"] == "10.0.0.1"


def test_api_port_filter(test_db):
    from app.app import create_app

    app = create_app()
    client = app.test_client()

    response = client.get("/api/packets?destination_port=53")

    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == 1
    assert data["packets"][0]["destination_port"] == 53


def test_api_combined_filters(test_db):
    from app.app import create_app

    app = create_app()
    client = app.test_client()

    response = client.get(
        "/api/packets?source_ip=10.0.0.1&protocol=UDP"
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == 1
    assert data["packets"][0]["protocol"] == "UDP"


def test_api_invalid_filter(test_db):
    from app.app import create_app

    app = create_app()
    client = app.test_client()

    response = client.get("/api/packets?protocol=INVALID")

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_api_invalid_ip(test_db):
    from app.app import create_app

    app = create_app()
    client = app.test_client()

    response = client.get("/api/packets?source_ip=not-an-ip")

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_api_invalid_port(test_db):
    from app.app import create_app

    app = create_app()
    client = app.test_client()

    response = client.get("/api/packets?source_port=99999")

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_api_no_filters_returns_all_packets(test_db):
    from app.app import create_app

    app = create_app()
    client = app.test_client()

    response = client.get("/api/packets")

    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == 3