"""Measure insert throughput and API latency on a temporary database.

Prints only what it actually measures; paste YOUR output into docs/performance.md.
Usage: python scripts/benchmark.py [N_PACKETS]
"""

import resource
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import database  # noqa: E402
from app import create_app  # noqa: E402

PROTOCOLS = [("TCP", "S"), ("UDP", None), ("ICMP", None)]
ENDPOINTS = [
    ("GET /api/packets", "/api/packets"),
    ("GET /api/packets?protocol=TCP", "/api/packets?protocol=TCP"),
    ("GET /api/packets?source_ip=10.0.0", "/api/packets?source_ip=10.0.0"),
    ("GET /api/stats", "/api/stats"),
]


def make_packets(n):
    packets = []
    for i in range(n):
        protocol, flags = PROTOCOLS[i % 3]
        packets.append({
            "timestamp": f"2026-10-01 10:{(i // 60) % 60:02d}:{i % 60:02d}",
            "source_ip": f"10.0.{i % 4}.{i % 250 + 1}",
            "destination_ip": f"192.168.1.{i % 200 + 1}",
            "source_port": None if protocol == "ICMP" else 1024 + i % 5000,
            "destination_port": None if protocol == "ICMP" else (80, 443, 53, 22)[i % 4],
            "protocol": protocol,
            "packet_size": 60 + i % 1400,
            "tcp_flags": flags,
        })
    return packets


def timed_ms(fn, repeat):
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    samples.sort()
    return statistics.mean(samples), samples[min(len(samples) - 1, int(0.95 * len(samples)))]


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    with tempfile.TemporaryDirectory() as tmp:
        database.DB_PATH = Path(tmp) / "bench.db"
        database.init_db()

        start = time.perf_counter()
        database.insert_packets(make_packets(n))
        bulk = time.perf_counter() - start

        single_n = min(n, 1000)
        start = time.perf_counter()
        for packet in make_packets(single_n):
            database.insert_packet(packet)
        single = time.perf_counter() - start

        client = create_app().test_client()
        print(f"rows in DB: {n + single_n}")
        print(f"bulk insert:   {n / bulk:,.0f} packets/s ({n} packets)")
        print(f"single insert: {single_n / single:,.0f} packets/s ({single_n} packets)")
        print(f"{'endpoint':40} {'mean ms':>9} {'p95 ms':>9}  (50 requests each)")
        for label, path in ENDPOINTS:
            mean, p95 = timed_ms(lambda p=path: client.get(p), 50)
            print(f"{label:40} {mean:9.2f} {p95:9.2f}")
        print(f"peak memory (max RSS): {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.1f} MB")
        print("note: packet drops need a real capture under load and are not measured here.")


if __name__ == "__main__":
    main()
