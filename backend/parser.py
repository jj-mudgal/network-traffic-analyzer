"""Packet parsing and metadata extraction utilities."""

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
    """Return the packet timestamp as a float, or None."""
    if packet is None:
        return None

    timestamp = getattr(packet, "time", None)
    if timestamp is None:
        return None

    return float(timestamp)


def extract_protocol(packet: Packet):
    """Return TCP, UDP, ICMP, or OTHER."""
    if packet is None:
        return "OTHER"

    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"

    return "OTHER"


def extract_ports(packet: Packet):
    """Return source and destination ports for TCP/UDP packets."""
    if packet is None:
        return None, None

    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport

    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport

    return None, None


def extract_tcp_flags(packet: Packet):
    """Return TCP flags as a string, or None for non-TCP packets."""
    if packet is None or not packet.haslayer(TCP):
        return None

    return str(packet[TCP].flags)


def parse_packet(packet: Packet):
    """Extract protocol metadata in a format suitable for other modules."""
    if packet is None:
        return {}

    source_port, destination_port = extract_ports(packet)

    return {
        "timestamp": extract_timestamp(packet),
        "source_ip": extract_source_ip(packet),
        "destination_ip": extract_destination_ip(packet),
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": extract_protocol(packet),
        "packet_size": len(packet),
        "tcp_flags": extract_tcp_flags(packet),
    }