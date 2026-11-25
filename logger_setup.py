import os
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

from config import LOG_PATH

AUTH_ERRORS = {
    "invalid_password",
    "authentication_failed",
    "key_mismatch",
    "key_not_found"
}

ANOMALY_THRESHOLD = 3
ANOMALY_WINDOW = 300


class JSONFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.getMessage()
        }

        data.update(getattr(record, "extra", {}))
        return json.dumps(data, ensure_ascii=False)


def get_logger():
    path = Path(LOG_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)

    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)

    logger = logging.getLogger("aeslab")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)

    return logger


def read_events():
    path = Path(LOG_PATH)

    if not path.exists():
        return []

    events = []

    with path.open(encoding="utf-8") as fp:
        for line in fp:
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
            except ValueError:
                continue

    return events


def recent_auth_failures():
    now = datetime.now(timezone.utc)
    count = 0

    for event in read_events():
        if event.get("reason") not in AUTH_ERRORS:
            continue

        if event.get("ok") is not False:
            continue

        try:
            ts = datetime.fromisoformat(event["ts"])
            age = (now - ts).total_seconds()

            if 0 <= age <= ANOMALY_WINDOW:
                count += 1

        except (ValueError, KeyError, TypeError):
            continue

    return count


def record_event(operation, ok, mode=None,
                 reason=None, elapsed_ms=None):

    logger = get_logger()

    details = {
        "ok": ok,
        "mode": mode,
        "reason": reason,
        "elapsed_ms": elapsed_ms
    }

    level = logging.INFO if ok else logging.WARNING

    logger.log(
        level, operation,
        extra={"extra": details}
    )

    if not ok and reason in AUTH_ERRORS:
        count = recent_auth_failures()

        if count == ANOMALY_THRESHOLD:
            logger.error(
                "AUTH_ANOMALY",
                extra={"extra": {
                    "failures": count,
                    "window_seconds": ANOMALY_WINDOW
                }}
            )

            print("SECURITY ALERT: Repeated authentication failures")


def show_summary():
    events = read_events()

    levels = Counter(
        event.get("level", "UNKNOWN")
        for event in events
    )

    failures = Counter(
        event.get("reason", "legacy_event")
        for event in events
        if event.get("ok") is False
    )

    print("=== SECURITY LOG SUMMARY ===")
    print("Total events:", len(events))

    for level in ("INFO", "WARNING", "ERROR"):
        print(f"{level}: {levels[level]}")

    print("\nFailure reasons:")

    for reason, count in failures.items():
        print(f"  {reason}: {count}")

    anomalies = sum(
        event.get("event") == "AUTH_ANOMALY"
        for event in events
    )

    print("\nAuthentication anomalies:", anomalies)
    print("Recent authentication failures:",
          recent_auth_failures())


if __name__ == "__main__":
    show_summary()
