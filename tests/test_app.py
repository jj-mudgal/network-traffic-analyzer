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