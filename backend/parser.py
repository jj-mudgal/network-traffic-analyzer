"""Packet metadata extraction utilities."""

from scapy.packet import Packet
from scapy.layers.inet import IP


def extract_source_ip(packet: Packet):
    """Return the source IPv4 address, or None if unavailable."""
    if packet is None or not packet.haslayer(IP):
        return None
    return packet[IP].src


def extract_destination_ip(packet: Packet):
    """Return the destination IPv4 address, or None if unavailable."""
    if packet is None or not packet.haslayer(IP):
        return None
    return packet[IP].dst


def extract_timestamp(packet: Packet):
    """Return the packet capture timestamp as a float, or None."""
    if packet is None:
        return None

    timestamp = getattr(packet, "time", None)
    if timestamp is None:
        return None

    return float(timestamp)


def parse_packet(packet: Packet):
    """Extract basic metadata in a format suitable for other modules."""
    return {
        "timestamp": extract_timestamp(packet),
        "source_ip": extract_source_ip(packet),
        "destination_ip": extract_destination_ip(packet),
    }