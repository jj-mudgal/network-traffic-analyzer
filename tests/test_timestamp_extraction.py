"""Unit tests for packet timestamp extraction."""

from scapy.all import IP

from backend.parser import extract_timestamp


def test_extract_timestamp_returns_valid_format():
    packet = IP(src="192.168.1.10", dst="8.8.8.8")
    timestamp = extract_timestamp(packet)

    assert timestamp is not None
    assert isinstance(timestamp, float)


def test_extract_timestamp_missing_field():
    packet = IP(src="192.168.1.10", dst="8.8.8.8")
    del packet.time

    assert extract_timestamp(packet) is None