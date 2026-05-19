"""
pipeline/interceptor.py
Intercepts raw data payloads, computes checksums, and adds provenance metadata.
Simulates a Spark/Airflow ingestion layer.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any


class DataInterceptor:
    """
    Stage 1 — Intercept raw data.

    Responsibilities:
    - Receive raw payload (list of dicts)
    - Compute SHA-256 checksum of the raw payload
    - Tag each record with provenance metadata (batch_id, captured_at)
    - Return an interception manifest
    """

    def __init__(self):
        self.batch_id = str(uuid.uuid4())

    def intercept(self, raw_data: list[dict]) -> dict[str, Any]:
        """
        Intercept a raw list of records.

        Returns:
            {
              "batch_id":    str,
              "captured_at": ISO timestamp,
              "record_count": int,
              "checksum":    SHA-256 hex of raw payload,
              "records":     list of records with added __meta
            }
        """
        raw_bytes = json.dumps(raw_data, sort_keys=True, ensure_ascii=False).encode()
        checksum  = hashlib.sha256(raw_bytes).hexdigest()
        captured_at = datetime.now(timezone.utc).isoformat()

        records = []
        for rec in raw_data:
            enriched = dict(rec)
            enriched["__meta"] = {
                "batch_id":    self.batch_id,
                "captured_at": captured_at,
                "source_hash": hashlib.md5(
                    json.dumps(rec, sort_keys=True).encode()
                ).hexdigest(),
            }
            records.append(enriched)

        return {
            "batch_id":    self.batch_id,
            "captured_at": captured_at,
            "record_count": len(records),
            "checksum":    checksum,
            "records":     records,
        }
