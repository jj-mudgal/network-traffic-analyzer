"""Tests for security detection rules and the alerts API."""

from datetime import datetime, timedelta, timezone

import database
from backend.security import (
    DEFAULT_CONFIG,
    DetectionConfig,
    detect_abnormal_traffic,
    detect_port_scans,
    get_detection_config,
)


def make_packet(timestamp, source_ip, destination_port, source_port=50000):
    """Create one packet metadata record for deterministic tests."""
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": "192.168.1.1",
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": "TCP",
        "packet_size": 60,
        "tcp_flags": "S",
    }


def test_port_scan_detection_creates_cautious_alert(db):
    now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    packet_time = (now - timedelta(seconds=2)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    database.insert_packets([
        make_packet(packet_time, "10.0.0.99", port)
        for port in (21, 22, 23)
    ])

    config = DetectionConfig(
        port_scan_distinct_ports_threshold=3,
        port_scan_time_window_seconds=30,
        abnormal_traffic_packets_per_second_threshold=1000,
        abnormal_traffic_window_seconds=5,
        alert_cooldown_seconds=60,
        detection_poll_interval_seconds=5,
    )

    alerts = detect_port_scans(config=config, now=now)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "10.0.0.99"
    assert alerts[0]["alert_type"] == "Possible Port Scan"
    assert alerts[0]["severity"] in {"Medium", "High"}
    assert "not proof of an attack" in alerts[0]["description"]


def test_port_scan_below_threshold_does_not_alert(db):
    now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    packet_time = (now - timedelta(seconds=2)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    database.insert_packets([
        make_packet(packet_time, "10.0.0.44", port)
        for port in (80, 443)
    ])

    config = DetectionConfig(
        port_scan_distinct_ports_threshold=3,
        port_scan_time_window_seconds=30,
        abnormal_traffic_packets_per_second_threshold=1000,
        abnormal_traffic_window_seconds=5,
        alert_cooldown_seconds=60,
        detection_poll_interval_seconds=5,
    )

    assert detect_port_scans(config=config, now=now) == []
    assert database.get_alerts(limit=10) == []


def test_duplicate_port_scan_alert_is_suppressed_during_cooldown(db):
    now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    packet_time = (now - timedelta(seconds=2)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    database.insert_packets([
        make_packet(packet_time, "10.0.0.99", port)
        for port in (21, 22, 23)
    ])

    config = DetectionConfig(
        port_scan_distinct_ports_threshold=3,
        port_scan_time_window_seconds=30,
        abnormal_traffic_packets_per_second_threshold=1000,
        abnormal_traffic_window_seconds=5,
        alert_cooldown_seconds=60,
        detection_poll_interval_seconds=5,
    )

    first = detect_port_scans(config=config, now=now)
    second = detect_port_scans(config=config, now=now)

    assert len(first) == 1
    assert second == []
    assert len(database.get_alerts(limit=10)) == 1


def test_abnormal_traffic_detection_creates_alert(db):
    now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    packet_time = (now - timedelta(seconds=1)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    database.insert_packets([
        make_packet(packet_time, "10.0.0.55", 80, source_port=50000 + i)
        for i in range(11)
    ])

    config = DetectionConfig(
        port_scan_distinct_ports_threshold=100,
        port_scan_time_window_seconds=30,
        abnormal_traffic_packets_per_second_threshold=2,
        abnormal_traffic_window_seconds=5,
        alert_cooldown_seconds=60,
        detection_poll_interval_seconds=5,
    )

    alerts = detect_abnormal_traffic(config=config, now=now)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "10.0.0.55"
    assert alerts[0]["alert_type"] == "Abnormal Traffic"
    assert alerts[0]["severity"] in {"Medium", "High"}
    assert "not confirmation of an attack" in alerts[0]["description"]


def test_abnormal_traffic_at_exact_threshold_does_not_alert(db):
    now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
    packet_time = (now - timedelta(seconds=1)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # 10 packets / 5 seconds = exactly 2 packets per second.
    database.insert_packets([
        make_packet(packet_time, "10.0.0.56", 80, source_port=51000 + i)
        for i in range(10)
    ])

    config = DetectionConfig(
        port_scan_distinct_ports_threshold=100,
        port_scan_time_window_seconds=30,
        abnormal_traffic_packets_per_second_threshold=2,
        abnormal_traffic_window_seconds=5,
        alert_cooldown_seconds=60,
        detection_poll_interval_seconds=5,
    )

    assert detect_abnormal_traffic(config=config, now=now) == []
    assert database.get_alerts(limit=10) == []


def test_invalid_environment_threshold_uses_default(monkeypatch):
    monkeypatch.setenv(
        "PORT_SCAN_DISTINCT_PORTS_THRESHOLD",
        "not-a-number",
    )

    config = get_detection_config()

    assert (
        config.port_scan_distinct_ports_threshold
        == DEFAULT_CONFIG.port_scan_distinct_ports_threshold
    )

    monkeypatch.setenv("PORT_SCAN_DISTINCT_PORTS_THRESHOLD", "0")
    config = get_detection_config()

    assert (
        config.port_scan_distinct_ports_threshold
        == DEFAULT_CONFIG.port_scan_distinct_ports_threshold
    )


def test_alerts_api_rejects_invalid_severity(client):
    response = client.get("/api/alerts?severity=Critical")

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_alerts_api_rejects_invalid_limit(client):
    for invalid_limit in ("abc", "0", "-1", "501"):
        response = client.get(
            f"/api/alerts?limit={invalid_limit}"
        )

        assert response.status_code == 400
        assert "error" in response.get_json()


def test_alerts_api_returns_filtered_alerts(client, db):
    database.insert_alert({
        "timestamp": "2026-10-11 10:00:00",
        "source_ip": "10.0.0.1",
        "alert_type": "Possible Port Scan",
        "severity": "High",
        "description": "Possible suspicious port activity.",
    })
    database.insert_alert({
        "timestamp": "2026-10-11 10:00:01",
        "source_ip": "10.0.0.2",
        "alert_type": "Abnormal Traffic",
        "severity": "Low",
        "description": "Possible unusual traffic volume.",
    })

    response = client.get("/api/alerts?severity=high&limit=10")

    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == 1
    assert data["alerts"][0]["severity"] == "High"


def test_alert_config_api_returns_effective_thresholds(client):
    response = client.get("/api/alerts/config")

    assert response.status_code == 200
    data = response.get_json()

    thresholds = data["thresholds"]
    assert thresholds["port_scan_distinct_ports_threshold"] > 0
    assert thresholds["port_scan_time_window_seconds"] > 0
    assert thresholds["abnormal_traffic_packets_per_second_threshold"] > 0
    assert thresholds["abnormal_traffic_window_seconds"] > 0
    assert thresholds["alert_cooldown_seconds"] > 0

    assert data["valid_severities"] == ["High", "Low", "Medium"]


def test_manual_scan_api_runs_detection(client, db, monkeypatch):
    monkeypatch.setenv("PORT_SCAN_DISTINCT_PORTS_THRESHOLD", "2")
    monkeypatch.setenv("PORT_SCAN_TIME_WINDOW_SECONDS", "60")
    monkeypatch.setenv(
        "ABNORMAL_TRAFFIC_PACKETS_PER_SECOND_THRESHOLD",
        "100000",
    )

    packet_time = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    database.insert_packets([
        make_packet(packet_time, "10.0.0.77", 80),
        make_packet(packet_time, "10.0.0.77", 443),
    ])

    response = client.post("/api/alerts/scan")

    assert response.status_code == 200
    data = response.get_json()

    assert data["count"] == 1
    assert data["alerts"][0]["alert_type"] == "Possible Port Scan"
    assert "not confirmed attacks" in data["message"]

def test_background_detection_loop_starts_once_and_stops(db):
    from backend.security import (
        start_detection_loop,
        stop_detection_loop,
    )

    first_thread = start_detection_loop()

    try:
        second_thread = start_detection_loop()

        # Starting again must not create another worker.
        assert first_thread is second_thread
        assert first_thread.is_alive()
    finally:
        stop_detection_loop()

    assert not first_thread.is_alive()