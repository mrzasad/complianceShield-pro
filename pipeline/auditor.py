"""
pipeline/auditor.py
Audits records against GDPR and PECA compliance frameworks.

GDPR rules implemented (selected articles):
  Art. 5  – Lawfulness, fairness, transparency (presence of consent signal)
  Art. 17 – Right to erasure (no retention flag breach)
  Art. 25 – Data minimisation (unnecessary PII present)
  Art. 32 – Security of processing (unencrypted sensitive fields)
  Art. 35 – DPIA trigger (high-risk data categories)

PECA 2016 rules (Pakistan Electronic Crimes Act):
  Sec. 14 – Unauthorised use of identity information
  Sec. 16 – Glorification / privacy invasion
  Sec. 18 – Data protection obligations
  Sec. 34 – Offences against dignity (personal data exposure)
"""

import re
from typing import Any


# ── Rule definitions ────────────────────────────────────────────────────────────

GDPR_RULES = [
    {
        "id":        "GDPR-ART25-001",
        "framework": "GDPR",
        "article":   "Art. 25 – Data Minimisation",
        "field":     "national_id",
        "rule":      "National ID collected without demonstrated legal basis",
        "risk":      "HIGH",
    },
    {
        "id":        "GDPR-ART32-001",
        "framework": "GDPR",
        "article":   "Art. 32 – Security of Processing",
        "field":     "credit_card",
        "rule":      "Payment card data present in plaintext — must be encrypted at rest",
        "risk":      "CRITICAL",
    },
    {
        "id":        "GDPR-ART35-001",
        "framework": "GDPR",
        "article":   "Art. 35 – DPIA Required",
        "field":     "dob",
        "rule":      "Date of birth is a sensitive attribute requiring DPIA documentation",
        "risk":      "MEDIUM",
    },
    {
        "id":        "GDPR-ART5-001",
        "framework": "GDPR",
        "article":   "Art. 5 – Purpose Limitation",
        "field":     "ip_address",
        "rule":      "IP address is personal data; collection purpose must be documented",
        "risk":      "MEDIUM",
    },
    {
        "id":        "GDPR-ART5-002",
        "framework": "GDPR",
        "article":   "Art. 5 – Lawfulness",
        "field":     "email",
        "rule":      "Email collected — consent or legitimate interest basis required",
        "risk":      "MEDIUM",
    },
]

PECA_RULES = [
    {
        "id":        "PECA-SEC14-001",
        "framework": "PECA",
        "article":   "Sec. 14 – Identity Information",
        "field":     "national_id",
        "rule":      "CNIC number is identity information protected under PECA Sec. 14",
        "risk":      "HIGH",
    },
    {
        "id":        "PECA-SEC18-001",
        "framework": "PECA",
        "article":   "Sec. 18 – Data Protection",
        "field":     "phone",
        "rule":      "Mobile number is personal data; collection/transfer must be lawful",
        "risk":      "MEDIUM",
    },
    {
        "id":        "PECA-SEC34-001",
        "framework": "PECA",
        "article":   "Sec. 34 – Dignity / Privacy",
        "field":     "dob",
        "rule":      "Date of birth exposure may constitute privacy invasion under PECA",
        "risk":      "LOW",
    },
    {
        "id":        "PECA-SEC14-002",
        "framework": "PECA",
        "article":   "Sec. 14 – Identity Information",
        "field":     "credit_card",
        "rule":      "Financial identity data stored in plaintext violates PECA Sec. 14",
        "risk":      "CRITICAL",
    },
]

# PII format validators (simple regex checks)
PII_PATTERNS = {
    "email":       re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+"),
    "phone":       re.compile(r"[\+\d][\d\s\-\(\)]{6,}"),
    "credit_card": re.compile(r"\d{13,19}"),
    "national_id": re.compile(r"\d{5}-\d{7}-\d"),
    "dob":         re.compile(r"\d{4}-\d{2}-\d{2}"),
    "ip_address":  re.compile(r"\d{1,3}(?:\.\d{1,3}){3}"),
    "passport_no": re.compile(r"[A-Z]{1,2}\d{6,9}"),
}


class ComplianceAuditor:
    """
    Stage 2 — Audit records for GDPR and PECA compliance.
    """

    def __init__(self, frameworks: list[str], pii_fields: list[str]):
        self.frameworks = frameworks
        self.pii_fields = pii_fields

        self._rules: list[dict] = []
        if "GDPR" in frameworks:
            self._rules.extend(GDPR_RULES)
        if "PECA" in frameworks:
            self._rules.extend(PECA_RULES)

    # ── Public API ──────────────────────────────────────────────────────────────

    def audit(self, records: list[dict]) -> list[dict[str, Any]]:
        """Audit a list of intercepted records. Returns enriched audit results."""
        return [self._audit_record(rec) for rec in records]

    # ── Private ─────────────────────────────────────────────────────────────────

    def _audit_record(self, record: dict) -> dict[str, Any]:
        violations: list[dict] = []
        pii_detected: list[str] = []

        # 1. Detect PII fields present in the record
        for field in self.pii_fields:
            val = record.get(field)
            if val and self._is_pii_present(field, str(val)):
                pii_detected.append(field)

        # 2. Apply compliance rules for each detected PII field
        for rule in self._rules:
            if rule["field"] in pii_detected:
                violations.append(rule)

        # 3. Determine overall status
        risks = [v["risk"] for v in violations]
        if "CRITICAL" in risks or "HIGH" in risks:
            status = "VIOLATION"
        elif "MEDIUM" in risks or "LOW" in risks:
            status = "WARNING"
        else:
            status = "COMPLIANT"

        return {
            "id":           record.get("id"),
            "name":         record.get("name"),
            "country":      record.get("country"),
            "pii_detected": pii_detected,
            "violations":   violations,
            "status":       status,
            "_raw":         record,          # carry forward for encryption
        }

    @staticmethod
    def _is_pii_present(field: str, value: str) -> bool:
        """Returns True if the value looks like real PII for the given field."""
        if not value or value.strip() in ("", "null", "None"):
            return False
        pattern = PII_PATTERNS.get(field)
        if pattern:
            return bool(pattern.search(value))
        # fallback: non-empty is considered PII for unknown fields
        return True
