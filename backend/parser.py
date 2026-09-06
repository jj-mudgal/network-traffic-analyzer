"""Packet metadata extraction utilities."""

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP


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
    if packet is None:
        return {}

    protocol = "OTHER"
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    source_port = None
    destination_port = None
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        source_port = packet.sport
        destination_port = packet.dport

    tcp_flags = None
    if packet.haslayer(TCP):
        tcp_flags = str(packet[TCP].flags)

    return {
        "timestamp": extract_timestamp(packet),
        "source_ip": extract_source_ip(packet),
        "destination_ip": extract_destination_ip(packet),
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_size": len(packet),
        "tcp_flags": tcp_flags,
    }