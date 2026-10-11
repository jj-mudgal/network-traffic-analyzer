"""Rule-based security detection for the Network Traffic Analyzer.

Alerts indicate potentially suspicious patterns, not confirmed attacks.
Only stored packet metadata is analyzed.
"""

import logging
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

import database

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DetectionConfig:
    port_scan_distinct_ports_threshold: int = 15
    port_scan_time_window_seconds: int = 10
    abnormal_traffic_packets_per_second_threshold: int = 500
    abnormal_traffic_window_seconds: int = 5
    alert_cooldown_seconds: int = 60
    detection_poll_interval_seconds: int = 5


DEFAULT_CONFIG = DetectionConfig()

_DETECTION_LOCK = threading.RLock()
_LOOP_LOCK = threading.Lock()
_DETECTION_THREAD = None
_STOP_EVENT = None


def _positive_int_from_env(name, default):
    """Read a positive integer from the environment or use its default."""
    raw = os.getenv(name)

    if raw is None:
        return default

    try:
        value = int(raw.strip())
        if value <= 0:
            raise ValueError
        return value
    except (ValueError, AttributeError):
        logger.warning(
            "%s must be a positive integer; using default %s",
            name,
            default,
        )
        return default


def get_detection_config():
    """Read effective detection settings, including safe fallbacks."""
    defaults = DEFAULT_CONFIG

    return DetectionConfig(
        port_scan_distinct_ports_threshold=_positive_int_from_env(
            "PORT_SCAN_DISTINCT_PORTS_THRESHOLD",
            defaults.port_scan_distinct_ports_threshold,
        ),
        port_scan_time_window_seconds=_positive_int_from_env(
            "PORT_SCAN_TIME_WINDOW_SECONDS",
            defaults.port_scan_time_window_seconds,
        ),
        abnormal_traffic_packets_per_second_threshold=_positive_int_from_env(
            "ABNORMAL_TRAFFIC_PACKETS_PER_SECOND_THRESHOLD",
            defaults.abnormal_traffic_packets_per_second_threshold,
        ),
        abnormal_traffic_window_seconds=_positive_int_from_env(
            "ABNORMAL_TRAFFIC_WINDOW_SECONDS",
            defaults.abnormal_traffic_window_seconds,
        ),
        alert_cooldown_seconds=_positive_int_from_env(
            "ALERT_COOLDOWN_SECONDS",
            defaults.alert_cooldown_seconds,
        ),
        detection_poll_interval_seconds=_positive_int_from_env(
            "DETECTION_POLL_INTERVAL_SECONDS",
            defaults.detection_poll_interval_seconds,
        ),
    )


def get_detection_config_dict():
    """Return effective settings in a JSON-compatible dictionary."""
    return asdict(get_detection_config())


def _as_utc_datetime(value=None):
    """Normalize a datetime, timestamp string, or epoch value to UTC."""
    if value is None:
        return datetime.now(timezone.utc)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        try:
            value = datetime.fromisoformat(normalized)
        except ValueError:
            value = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")

    if not isinstance(value, datetime):
        raise TypeError(
            "now must be a datetime, epoch timestamp, or timestamp string"
        )

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _save_alert_if_not_recent(
    source_ip,
    alert_type,
    severity,
    description,
    config,
    now,
):
    """Store an alert only if the same source/type is outside its cooldown."""
    if database.has_recent_alert(
        alert_type,
        source_ip,
        window_seconds=config.alert_cooldown_seconds,
        now=now,
    ):
        return None

    record = {
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
        "alert_type": alert_type,
        "severity": severity,
        "description": description,
    }

    alert_id = database.insert_alert(record)
    return {"id": alert_id, **record}


def detect_port_scans(config=None, now=None):
    """Detect source IPs contacting many distinct ports within the window."""
    config = config or get_detection_config()
    reference_time = _as_utc_datetime(now)
    alerts = []

    with _DETECTION_LOCK:
        candidates = database.get_port_scan_candidates(
            window_seconds=config.port_scan_time_window_seconds,
            port_threshold=config.port_scan_distinct_ports_threshold,
            now=reference_time,
        )

        for candidate in candidates:
            source_ip = candidate["source_ip"]
            port_count = candidate["unique_ports"]
            threshold = config.port_scan_distinct_ports_threshold
            window = config.port_scan_time_window_seconds

            severity = (
                "High" if port_count >= threshold * 2 else "Medium"
            )
            description = (
                f"Source {source_ip} contacted {port_count} distinct "
                f"destination ports within {window} seconds "
                f"(configured threshold: {threshold}). "
                "This pattern can have benign explanations and is not "
                "proof of an attack."
            )

            alert = _save_alert_if_not_recent(
                source_ip=source_ip,
                alert_type="Possible Port Scan",
                severity=severity,
                description=description,
                config=config,
                now=reference_time,
            )

            if alert is not None:
                alerts.append(alert)

    return alerts


def detect_abnormal_traffic(config=None, now=None):
    """Detect sources whose average packet rate exceeds the configured limit."""
    config = config or get_detection_config()
    reference_time = _as_utc_datetime(now)
    alerts = []

    with _DETECTION_LOCK:
        window = config.abnormal_traffic_window_seconds
        rate_threshold = (
            config.abnormal_traffic_packets_per_second_threshold
        )

        # Strictly greater than the configured packets-per-second rate.
        minimum_packets = rate_threshold * window + 1

        candidates = database.get_source_packet_counts(
            window_seconds=window,
            threshold=minimum_packets,
            now=reference_time,
        )

        for candidate in candidates:
            source_ip = candidate["source_ip"]
            packet_count = candidate["packet_count"]
            observed_rate = packet_count / window

            severity = (
                "High"
                if observed_rate >= rate_threshold * 2
                else "Medium"
            )
            description = (
                f"Source {source_ip} generated {packet_count} packets "
                f"in the last {window} seconds "
                f"(approximately {observed_rate:.2f} packets/second; "
                f"configured threshold: {rate_threshold} packets/second). "
                "Legitimate traffic bursts can cause this pattern; "
                "this is not confirmation of an attack."
            )

            alert = _save_alert_if_not_recent(
                source_ip=source_ip,
                alert_type="Abnormal Traffic",
                severity=severity,
                description=description,
                config=config,
                now=reference_time,
            )

            if alert is not None:
                alerts.append(alert)

    return alerts


def run_detection(now=None):
    """Run all rules and return the alerts newly stored by this scan."""
    config = get_detection_config()
    reference_time = _as_utc_datetime(now)

    with _DETECTION_LOCK:
        port_scan_alerts = detect_port_scans(
            config=config,
            now=reference_time,
        )
        abnormal_alerts = detect_abnormal_traffic(
            config=config,
            now=reference_time,
        )

    return port_scan_alerts + abnormal_alerts


def _detection_loop(stop_event, interval_seconds):
    """Run detection periodically until a stop is requested."""
    while not stop_event.is_set():
        try:
            run_detection()
        except Exception:
            logger.exception("Background security detection failed")

        if stop_event.wait(interval_seconds):
            break


def start_detection_loop():
    """Start one daemon detection worker and return its thread."""
    global _DETECTION_THREAD, _STOP_EVENT

    with _LOOP_LOCK:
        if (
            _DETECTION_THREAD is not None
            and _DETECTION_THREAD.is_alive()
        ):
            return _DETECTION_THREAD

        config = get_detection_config()
        _STOP_EVENT = threading.Event()

        _DETECTION_THREAD = threading.Thread(
            target=_detection_loop,
            args=(
                _STOP_EVENT,
                config.detection_poll_interval_seconds,
            ),
            name="network-traffic-security-detection",
            daemon=True,
        )
        _DETECTION_THREAD.start()

        return _DETECTION_THREAD


def stop_detection_loop(timeout=3.0):
    """Request background worker shutdown and wait briefly."""
    global _DETECTION_THREAD, _STOP_EVENT

    with _LOOP_LOCK:
        thread = _DETECTION_THREAD
        stop_event = _STOP_EVENT

        if stop_event is not None:
            stop_event.set()

    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout=timeout)

    with _LOOP_LOCK:
        if thread is not None and not thread.is_alive():
            _DETECTION_THREAD = None
            _STOP_EVENT = None