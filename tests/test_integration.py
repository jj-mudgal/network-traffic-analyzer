"""Integration: stored packet metadata -> database -> Flask API -> dashboard assets."""

import pytest
from scapy.all import IP, TCP

import database
from backend.parser import parse_packet
from tests.sample_data import SAMPLE_PACKETS


def test_packets_api_matches_database(client, loaded_db):
    data = client.get("/api/packets").get_json()
    assert data["count"] == len(SAMPLE_PACKETS) == len(database.get_all_packets())


def test_stats_api_matches_database(client, loaded_db):
    api = client.get("/api/stats").get_json()
    direct = database.get_statistics()
    assert api["total_packets"] == direct["total"] == len(SAMPLE_PACKETS)
    assert api["total_bytes"] == sum(p["packet_size"] for p in SAMPLE_PACKETS)
    assert (api["tcp"], api["udp"], api["icmp"], api["other"]) == (2, 1, 1, 0)


@pytest.mark.parametrize("query,expected", [
    ("protocol=TCP", 2),
    ("protocol=udp", 1),
    ("source_ip=10.0.0", 3),
    ("destination_ip=8.8.8.8", 1),
    ("source_port=2000", 1),
    ("destination_port=80", 1),
    ("source_ip=10.0.0.1&protocol=TCP", 1),
    ("protocol=", 4),
])
def test_filtered_stats_match_filtered_packets(client, loaded_db, query, expected):
    packets = client.get(f"/api/packets?{query}").get_json()
    stats = client.get(f"/api/stats?{query}").get_json()
    assert packets["count"] == stats["total_packets"] == expected
    assert stats["total_bytes"] == sum(p["packet_size"] for p in packets["packets"])


@pytest.mark.parametrize("endpoint", ["/api/packets", "/api/stats"])
@pytest.mark.parametrize("query", [
    "protocol=BAD",
    "source_ip=not-an-ip",
    "destination_ip=%3Cscript%3E",
    "source_ip=%27%20OR%20%271%27%3D%271",
    "source_port=0",
    "source_port=99999",
    "destination_port=abc",
])
def test_invalid_input_returns_400_not_500(client, loaded_db, endpoint, query):
    response = client.get(f"{endpoint}?{query}")
    assert response.status_code == 400
    assert "error" in response.get_json()


@pytest.mark.parametrize("limit,status", [("2", 200), ("0", 400), ("-1", 400), ("x", 400), ("5000", 400)])
def test_limit_validation(client, loaded_db, limit, status):
    assert client.get(f"/api/packets?limit={limit}").status_code == status


def test_limit_is_applied(client, loaded_db):
    assert client.get("/api/packets?limit=2").get_json()["count"] == 2


def test_parsed_packet_flows_through_to_api(client, db):
    packet = IP(src="10.9.9.9", dst="1.1.1.1") / TCP(sport=4444, dport=443, flags="S")
    database.insert_packet(parse_packet(packet))

    data = client.get("/api/packets?source_ip=10.9.9.9").get_json()
    assert data["count"] == 1
    row = data["packets"][0]
    assert (row["destination_port"], row["protocol"], row["tcp_flags"]) == (443, "TCP", "S")
    assert isinstance(row["timestamp"], str)  # epoch float was normalised


def test_dashboard_assets_are_served(client):
    for path in ("/static/js/dashboard.js", "/static/css/style.css"):
        response = client.get(path)
        assert response.status_code == 200
        response.close()
