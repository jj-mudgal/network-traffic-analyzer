"""Shared sample packets: 2 TCP, 1 UDP, 1 ICMP, 744 bytes total."""

SAMPLE_PACKETS = [
    {"timestamp": "2026-10-01 10:00:01", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
     "source_port": 1000, "destination_port": 80, "protocol": "TCP", "packet_size": 100, "tcp_flags": "S"},
    {"timestamp": "2026-10-01 10:00:02", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.3",
     "source_port": 2000, "destination_port": 53, "protocol": "UDP", "packet_size": 80, "tcp_flags": None},
    {"timestamp": "2026-10-01 10:00:03", "source_ip": "10.0.0.4", "destination_ip": "10.0.0.1",
     "source_port": None, "destination_port": None, "protocol": "ICMP", "packet_size": 64, "tcp_flags": None},
    {"timestamp": "2026-10-01 10:00:04", "source_ip": "192.168.1.5", "destination_ip": "8.8.8.8",
     "source_port": 5000, "destination_port": 443, "protocol": "TCP", "packet_size": 500, "tcp_flags": "A"},
]
