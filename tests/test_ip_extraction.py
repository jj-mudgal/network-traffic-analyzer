"""Unit tests for source/destination IP extraction from packets."""

from scapy.all import IP, TCP

from backend.parser import (
    extract_source_ip,
    extract_destination_ip,
    parse_packet,
)


def test_extract_source_ip_valid_packet():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / TCP()
    assert extract_source_ip(packet) == "192.168.1.10"


def test_extract_destination_ip_valid_packet():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / TCP()
    assert extract_destination_ip(packet) == "8.8.8.8"


def test_extract_ip_malformed_packet_raises_or_returns_none():
    packet = TCP()
    assert extract_source_ip(packet) is None
    assert extract_destination_ip(packet) is None


def test_parsed_packet_can_be_passed_to_database_module():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / TCP()
    data = parse_packet(packet)

    assert data["source_ip"] == "192.168.1.10"
    assert data["destination_ip"] == "8.8.8.8"
    assert "timestamp" in data