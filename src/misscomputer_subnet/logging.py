# SPDX-License-Identifier: AGPL-3.0-only
"""Minimal structured logging without leaking request bodies or credentials."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        value: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage()[:512],
        }
        for key in (
            "request_id",
            "hotkey",
            "endpoint_id",
            "block",
            "netuid",
            "error",
            "finalized",
            "candidate_count",
            "invalid_axon_count",
            "hotkey_conflict_count",
            "uid_conflict_count",
            "axon_conflict_count",
            "attempt_count",
            "success_count",
            "failure_count",
            "carried_count",
            "backoff_count",
            "elapsed_ms",
            "refresh_timed_out",
            "discovery_failure",
        ):
            if hasattr(record, key):
                item = getattr(record, key)
                value[key] = item[:512] if isinstance(item, str) else item
        if record.exc_info:
            value["exception"] = self.formatException(record.exc_info)[:4096]
        return json.dumps(value, separators=(",", ":"))


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
