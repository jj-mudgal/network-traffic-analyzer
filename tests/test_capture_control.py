"""Tests for packet capture controls without elevated privileges."""

import time

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from app import create_app
import backend.capture as capture


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


@pytest.fixture(autouse=True)
def reset_capture_state():
    capture.stop_capture()
    with capture._state_lock:
        capture._state.update(
            running=False, interface=None, error=None, packets_captured=0
        )
        capture._capture_thread = None
    capture._stop_event.clear()
    yield
    capture.stop_capture()


def test_interfaces_endpoint(client, monkeypatch):
    monkeypatch.setattr("app.api.capture_routes.list_interfaces", lambda: ["eth-test", "lo"])
    response = client.get("/api/capture/interfaces")
    assert response.status_code == 200
    assert response.get_json()["interfaces"] == ["eth-test", "lo"]


def test_status_endpoint(client):
    response = client.get("/api/capture/status")
    assert response.status_code == 200
    assert response.get_json()["running"] is False
    assert "error" in response.get_json()


def test_start_requires_interface(client):
    response = client.post("/api/capture/start", json={})
    assert response.status_code == 400


def test_unknown_interface_returns_400(client, monkeypatch):
    monkeypatch.setattr(capture, "list_interfaces", lambda: ["known0"])
    response = client.post("/api/capture/start", json={"interface": "unknown0"})
    assert response.status_code == 400


def test_duplicate_start_returns_409_and_stop_works(client, monkeypatch):
    monkeypatch.setattr(capture, "list_interfaces", lambda: ["test0"])
    def fake_sniff(**kwargs):
        time.sleep(0.05)
        return []
    monkeypatch.setattr(capture, "sniff", fake_sniff)
    first = client.post("/api/capture/start", json={"interface": "test0"})
    assert first.status_code == 202
    second = client.post("/api/capture/start", json={"interface": "test0"})
    assert second.status_code == 409
    stopped = client.post("/api/capture/stop")
    assert stopped.status_code == 200
    assert stopped.get_json()["running"] is False


def test_permission_error_appears_in_status(client, monkeypatch):
    monkeypatch.setattr(capture, "list_interfaces", lambda: ["test0"])
    def permission_error(**kwargs):
        raise PermissionError("permission denied by test")
    monkeypatch.setattr(capture, "sniff", permission_error)
    response = client.post("/api/capture/start", json={"interface": "test0"})
    assert response.status_code == 202
    deadline = time.time() + 2
    status = client.get("/api/capture/status").get_json()
    while status["error"] is None and time.time() < deadline:
        time.sleep(0.01)
        status = client.get("/api/capture/status").get_json()
    assert status["running"] is False
    assert "permission denied by test" in status["error"]


def test_non_ip_packet_is_ignored(monkeypatch):
    inserted = []
    monkeypatch.setattr(capture, "insert_packet", inserted.append)
    assert capture._process_packet(Ether()) is False
    assert inserted == []


def test_ip_packet_is_stored(monkeypatch):
    inserted = []
    monkeypatch.setattr(capture, "insert_packet", inserted.append)
    packet = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1234, dport=443)
    assert capture._process_packet(packet) is True
    assert len(inserted) == 1
    assert inserted[0]["source_ip"] == "192.0.2.1"
