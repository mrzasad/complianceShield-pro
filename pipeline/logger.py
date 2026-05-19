"""
pipeline/logger.py
Immutable structured compliance audit logger.

Produces append-only log entries suitable for:
  - SIEM ingestion (JSON lines)
  - Regulatory audit trails (GDPR Art. 30 / PECA Sec. 18)
  - Export to Azure Monitor / Splunk / ELK
"""

from datetime import datetime, timezone
from typing import Any


class ComplianceLogger:
    """
    Stage 4 — Compliance audit logging.

    Each log entry is immutable once written (append-only list).
    Fields:
      timestamp  – UTC ISO 8601
      level      – INFO | WARN | ERROR | SUCCESS | ENCRYPT
      stage      – pipeline stage name
      message    – human-readable description
      metadata   – arbitrary key/value context dict
    """

    def __init__(self):
        self._logs: list[dict[str, Any]] = []

    def log(
        self,
        level:    str,
        stage:    str,
        message:  str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level":     level.upper(),
            "stage":     stage.upper(),
            "message":   message,
            "metadata":  metadata or {},
        }
        self._logs.append(entry)

    def get_logs(self) -> list[dict[str, Any]]:
        """Return a copy of all log entries (read-only view)."""
        return list(self._logs)

    def export_jsonlines(self) -> str:
        """Export logs as JSON Lines format for SIEM ingestion."""
        import json
        return "\n".join(json.dumps(entry) for entry in self._logs)

    def summary(self) -> dict[str, int]:
        from collections import Counter
        counts = Counter(e["level"] for e in self._logs)
        return dict(counts)
