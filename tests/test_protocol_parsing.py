"""Unit tests for TCP/UDP/ICMP packet parsing (Sprint 2)."""

from scapy.all import IP, TCP, UDP, ICMP, Raw

from backend.parser import (
    parse_packet,
    extract_ports,
    extract_protocol,
    extract_tcp_flags,
)


def test_parse_tcp_packet_extracts_correct_fields():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(
        sport=12345, dport=443, flags="S"
    )

    result = parse_packet(packet)

    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "8.8.8.8"
    assert result["source_port"] == 12345
    assert result["destination_port"] == 443
    assert result["protocol"] == "TCP"


def test_parse_udp_packet_extracts_correct_fields():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(
        sport=54321, dport=53
    )

    result = parse_packet(packet)

    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "8.8.8.8"
    assert result["source_port"] == 54321
    assert result["destination_port"] == 53
    assert result["protocol"] == "UDP"


def test_parse_icmp_packet_extracts_correct_fields():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / ICMP()

    result = parse_packet(packet)

    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "8.8.8.8"
    assert result["protocol"] == "ICMP"
    assert result["source_port"] is None
    assert result["destination_port"] is None


def test_extract_tcp_flags_returns_expected_flags():
    packet = IP() / TCP(flags="SA")

    assert extract_tcp_flags(packet) == "SA"


def test_parse_packet_size_matches_actual_length():
    packet = IP() / TCP(sport=1234, dport=80) / Raw(load=b"hello")

    result = parse_packet(packet)

    assert result["packet_size"] == len(packet)


def test_parse_unsupported_protocol_handled_gracefully():
    packet = IP() / Raw(load=b"test")

    result = parse_packet(packet)

    assert result["protocol"] == "OTHER"
    assert result["source_port"] is None
    assert result["destination_port"] is None