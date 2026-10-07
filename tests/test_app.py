"""Smoke tests for the Flask app (empty database)."""


def test_dashboard_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Network Traffic Analyzer" in response.data


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "network-traffic-analyzer-api"


def test_packets_endpoint_empty(client):
    data = client.get("/api/packets").get_json()
    assert data["packets"] == []
    assert data["count"] == 0


def test_stats_endpoint_empty(client):
    data = client.get("/api/stats").get_json()
    assert data["total_packets"] == 0
    assert data["tcp"] == data["udp"] == data["icmp"] == data["other"] == 0


def test_stats_endpoint_includes_analysis_fields(client):
    data = client.get("/api/stats").get_json()
    for key in (
        "total_packets", "total_bytes", "average_packet_size", "protocols",
        "protocol_bytes", "source_ports", "destination_ports", "top_source_ips",
        "top_destination_ips", "traffic_pairs", "port_activity",
    ):
        assert key in data


def test_alerts_endpoint_empty(client):
    data = client.get("/api/alerts").get_json()
    assert data["alerts"] == []
    assert data["count"] == 0
