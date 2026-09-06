"""Unit tests for TCP/UDP/ICMP packet parsing (Sprint 2)."""
import pytest
# from backend.parser import parse_packet, extract_ports, extract_protocol, extract_tcp_flags

def test_parse_tcp_packet_extracts_correct_fields():
    # TODO: build/mock a TCP packet, assert source_port, dest_port, protocol == 'TCP'
    pass

def test_parse_udp_packet_extracts_correct_fields():
    # TODO: mock UDP packet, assert protocol == 'UDP', ports extracted correctly
    pass

def test_parse_icmp_packet_extracts_correct_fields():
    # TODO: mock ICMP packet, assert protocol == 'ICMP' (ICMP has no ports — assert None/absent)
    pass

def test_extract_tcp_flags_returns_expected_flags():
    # TODO: mock TCP packet with SYN/ACK set, assert flags parsed correctly
    pass

def test_parse_packet_size_matches_actual_length():
    pass

def test_parse_unsupported_protocol_handled_gracefully():
    # protocols outside TCP/UDP/ICMP shouldn't crash the parser
    pass
