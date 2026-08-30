"""Unit tests for basic packet capture functionality."""

import pytest

from backend.capture import capture_packets


def test_capture_handles_no_interface_gracefully():
    with pytest.raises(ValueError):
        capture_packets(None)


def test_capture_returns_packet_objects(monkeypatch):
    from scapy.layers.inet import IP

    sample_packet = IP(src="192.168.1.10", dst="8.8.8.8")

    monkeypatch.setattr(
        "backend.capture.sniff",
        lambda **kwargs: [sample_packet],
    )

    packets = capture_packets("test-interface", count=1)

    assert len(packets) == 1
    assert packets[0].haslayer(IP)