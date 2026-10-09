# API Reference

All responses are JSON. Invalid input returns `400 {"error": "..."}`, never a 500.

## Packets and statistics

Both endpoints accept the **same** filters, so the table, stat cards and charts always describe the same rows.

| Param | Rule |
|---|---|
| `protocol` | `TCP`, `UDP` or `ICMP` (case-insensitive) |
| `source_ip`, `destination_ip` | full IPv4/IPv6 address or a partial prefix such as `192.168.1` (substring match) |
| `source_port`, `destination_port` | integer 1-65535 |
| `limit` (packets only) | integer 1-1000, default 200 |

| Endpoint | Returns |
|---|---|
| `GET /api/packets` | `{"packets": [...], "count": n}` newest first |
| `GET /api/stats` | `total_packets`, `total_bytes`, `average_packet_size`, `tcp`, `udp`, `icmp`, `other`, `protocols`, `protocol_bytes`, `source_ports`, `destination_ports`, `top_source_ips`, `top_destination_ips`, `traffic_pairs`, `port_activity` |
| `GET /api/health` | service status |

## Alerts

| Endpoint | Description |
|---|---|
| `GET /api/alerts?severity=&limit=` | alert history (`Low`/`Medium`/`High`, limit 1-500) |
| `POST /api/alerts/scan` | run detection now; returns newly created alerts |
| `GET /api/alerts/config` | current detection thresholds |

Thresholds come from `.env`: `PORT_SCAN_DISTINCT_PORTS_THRESHOLD`, `PORT_SCAN_TIME_WINDOW_SECONDS`, `ABNORMAL_TRAFFIC_PACKETS_PER_SECOND_THRESHOLD`, `ABNORMAL_TRAFFIC_WINDOW_SECONDS`, `ALERT_COOLDOWN_SECONDS`.

## Capture

| Endpoint | Description |
|---|---|
| `GET /api/capture/interfaces` | available interfaces |
| `GET /api/capture/status` | `running`, `interface`, `packets_stored`, `error` |
| `POST /api/capture/start` | body `{"interface": "eth0"}`; 400 invalid/unknown, 409 already running |
| `POST /api/capture/stop` | stop capture |

Live capture needs root (raw sockets); a permission error shows up in `status.error`.
