from app.app import create_app
def test_index():
    app = create_app()
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200

    data = response.get_json()

    assert data["name"] == "Network Traffic Analyzer"
    assert data["status"] == "running"


def test_health():
    app = create_app()
    client = app.test_client()

    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "healthy"
    assert data["service"] == "network-traffic-analyzer-api"


def test_packets_endpoint():
    app = create_app()
    client = app.test_client()

    response = client.get("/api/packets")

    assert response.status_code == 200

    data = response.get_json()

    assert data["packets"] == []
    assert data["count"] == 0


def test_stats_endpoint():
    app = create_app()
    client = app.test_client()

    response = client.get("/api/stats")

    assert response.status_code == 200

    data = response.get_json()

    assert data["total_packets"] == 0
    assert data["tcp"] == 0
    assert data["udp"] == 0
    assert data["icmp"] == 0


def test_alerts_endpoint():
    app = create_app()
    client = app.test_client()

    response = client.get("/api/alerts")

    assert response.status_code == 200

    data = response.get_json()

    assert data["alerts"] == []
    assert data["count"] == 0

    def test_stats_endpoint_includes_analysis_fields():
        app = create_app()
    client = app.test_client()

    response = client.get("/api/stats")

    assert response.status_code == 200

    data = response.get_json()

    assert "total_packets" in data
    assert "total_bytes" in data
    assert "average_packet_size" in data
    assert "protocols" in data
    assert "protocol_bytes" in data
    assert "source_ports" in data
    assert "destination_ports" in data
    assert "top_source_ips" in data
    assert "top_destination_ips" in data
    assert "traffic_pairs" in data
    assert "port_activity" in data