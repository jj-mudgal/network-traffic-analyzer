"""Unit tests for traffic statistics calculations (Sprint 3)."""
import pytest

# from backend.statistics import compute_traffic_stats
# from database import get_all_packets, insert_packet


def test_total_packet_count_matches_stored_rows():
    # TODO: insert N packets, assert stats["total"] == N
    pass


def test_protocol_breakdown_counts_are_correct():
    # TODO: insert known mix of TCP/UDP/ICMP, assert each count matches
    pass


def test_statistics_with_empty_database_returns_zeroes():
    # TODO: assert all counts are 0 when no packets exist
    pass


def test_statistics_ignore_malformed_protocol_values():
    # TODO: insert a packet with an unexpected protocol value,
    # assert it's bucketed correctly (e.g. under "OTHER") without crashing
    pass
