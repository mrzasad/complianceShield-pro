

"""
Compliance Data Pipeline - PECA/GDPR Auditor
Streamlit UI for intercepting, auditing, encrypting, and logging data
"""

import os
import sys

# Append the directory containing the 'pipeline' folder to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Your original imports will now work perfectly:
from pipeline.interceptor import DataInterceptor



from pipeline.interceptor import DataInterceptor
from pipeline.auditor import ComplianceAuditor
from pipeline.encryptor import DataEncryptor
from pipeline.logger import ComplianceLogger
from pipeline.spark_engine import SparkPipelineEngine

import streamlit as st
import json
import pandas as pd
import time
from datetime import datetime

# ─── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ComplianceShield | PECA/GDPR Pipeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

* { font-family: 'IBM Plex Sans', sans-serif; }
code, .mono { font-family: 'IBM Plex Mono', monospace; }

/* Light theme - Clean white background */
.stApp {
    background-color: #ffffff;
    color: #212529;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #f8f9fa;
    border-right: 1px solid #dee2e6;
}

/* Status badges - Light theme compatible */
.badge-compliant {
    background: #d4edda; color: #155724; border: 1px solid #c3e6cb;
    padding: 2px 10px; border-radius: 3px; font-family: 'IBM Plex Mono'; font-size: 11px;
}
.badge-violation {
    background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb;
    padding: 2px 10px; border-radius: 3px; font-family: 'IBM Plex Mono'; font-size: 11px;
}
.badge-warning {
    background: #fff3cd; color: #856404; border: 1px solid #ffeeba;
    padding: 2px 10px; border-radius: 3px; font-family: 'IBM Plex Mono'; font-size: 11px;
}
.badge-encrypted {
    background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb;
    padding: 2px 10px; border-radius: 3px; font-family: 'IBM Plex Mono'; font-size: 11px;
}

/* Cards */
.metric-card {
    background: #ffffff;
    border: 1px solid #dee2e6;
    border-radius: 4px;
    padding: 16px 20px;
    margin-bottom: 10px;
}
.metric-value {
    font-size: 2rem; font-weight: 700;
    font-family: 'IBM Plex Mono'; color: #0d6efd;
}
.metric-label {
    font-size: 0.75rem; color: #6c757d; text-transform: uppercase; letter-spacing: 2px;
}

/* Log console */
.log-console {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 4px;
    padding: 14px;
    font-family: 'IBM Plex Mono';
    font-size: 12px;
    max-height: 320px;
    overflow-y: auto;
    color: #212529;
}
.log-info    { color: #0d6efd; }
.log-warn    { color: #ffc107; }
.log-error   { color: #dc3545; }
.log-success { color: #198754; }
.log-encrypt { color: #6f42c1; }

/* Header */
.shield-header {
    background: #f8f9fa;
    border-bottom: 2px solid #dee2e6;
    padding: 18px 28px;
    margin: -1rem -1rem 1.5rem -1rem;
}
.shield-title {
    font-size: 1.4rem; font-weight: 700; color: #212529; letter-spacing: 1px;
}
.shield-sub {
    font-size: 0.75rem; color: #6c757d; letter-spacing: 3px; text-transform: uppercase;
}

/* Pipeline stage */
.stage-box {
    border: 1px solid #dee2e6;
    border-radius: 4px;
    padding: 12px;
    background: #ffffff;
    margin-bottom: 8px;
}
.stage-active  { border-color: #0d6efd; background: #e7f1ff; }
.stage-done    { border-color: #198754; background: #d4edda; }
.stage-error   { border-color: #dc3545; background: #f8d7da; }

hr { border-color: #dee2e6; }
</style>
""", unsafe_allow_html=True)

# ─── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="shield-header">
  <div class="shield-title">🛡️ &nbsp;ComplianceShield Pipeline</div>
  <div class="shield-sub">PECA · GDPR · Data Interception · Encryption · Audit Logging</div>
</div>
""", unsafe_allow_html=True)

# ─── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Pipeline Configuration")
    st.divider()

    engine_choice = st.selectbox(
        "Processing Engine",
        ["Apache Spark (Simulated)", "Airflow DAG (Simulated)", "Direct Python"],
        index=0
    )

    st.markdown("**Compliance Frameworks**")
    enable_gdpr = st.toggle("GDPR", value=True)
    enable_peca = st.toggle("PECA (Pakistan)", value=True)

    st.markdown("**Encryption**")
    enc_algo = st.selectbox("Algorithm", ["AES-256-GCM", "Fernet (AES-128-CBC)", "RSA-OAEP + AES"])
    mask_display = st.toggle("Mask values in UI", value=True)

    st.markdown("**PII Detection**")
    pii_fields = st.multiselect(
        "Fields to audit",
        ["email", "phone", "national_id", "dob", "credit_card",
         "ip_address", "name", "address", "passport_no"],
        default=["email", "phone", "national_id", "dob", "credit_card"]
    )

    st.divider()
    st.markdown("**Log Settings**")
    log_format = st.selectbox("Log Format", ["JSON (structured)", "Plain text"])
    export_logs = st.toggle("Export audit log on run", value=True)

    st.divider()
    st.markdown("""
    <div style='font-size:11px;color:#2d4a6a;font-family:IBM Plex Mono'>
    v1.0.0 · ComplianceShield<br>
    PECA 2016 · GDPR Art. 25/32/35
    </div>
    """, unsafe_allow_html=True)

# ─── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "📥 Data Input & Intercept",
    "🔍 Compliance Audit",
    "🔐 Encryption",
    "📋 Audit Logs"
])

# ─── Initialise session state ──────────────────────────────────────────────────
if "raw_data"         not in st.session_state: st.session_state.raw_data         = None
if "audit_results"    not in st.session_state: st.session_state.audit_results    = None
if "encrypted_data"   not in st.session_state: st.session_state.encrypted_data   = None
if "audit_logs"       not in st.session_state: st.session_state.audit_logs       = []
if "pipeline_ran"     not in st.session_state: st.session_state.pipeline_ran     = False
if "encryptor"        not in st.session_state: st.session_state.encryptor        = DataEncryptor(enc_algo)

SAMPLE_DATA = [
    {"id": 1, "name": "Alice Johnson",    "email": "alice@example.com",   "phone": "+1-555-0101", "national_id": "42101-1234567-1", "dob": "1990-03-15", "credit_card": "4111111111111111", "ip_address": "192.168.1.10",  "account_balance": 5200.00, "transaction_type": "purchase",  "country": "PK"},
    {"id": 2, "name": "Bob Martinez",     "email": "bob@company.org",     "phone": "+44-7911-123456", "national_id": "35202-9876543-2", "dob": "1985-07-22", "credit_card": "5500005555555559", "ip_address": "10.0.0.45",     "account_balance": 12800.50,"transaction_type": "transfer",  "country": "DE"},
    {"id": 3, "name": "Carol Chen",       "email": "carol@domain.net",    "phone": "+92-300-1234567", "national_id": "54400-7654321-3", "dob": "1992-11-08", "credit_card": "378282246310005",  "ip_address": "172.16.0.22",   "account_balance": 890.75,  "transaction_type": "withdrawal","country": "PK"},
    {"id": 4, "name": "David O'Brien",    "email": "david@mail.co",       "phone": "+49-30-12345678", "national_id": "61101-3456789-4", "dob": "1978-05-30", "credit_card": "6011111111111117", "ip_address": "203.0.113.55",  "account_balance": 45000.00,"transaction_type": "purchase",  "country": "IE"},
    {"id": 5, "name": "Eva Kowalski",     "email": "eva@enterprise.eu",   "phone": "+48-601-234567",  "national_id": "30103-8765432-5", "dob": "2000-01-19", "credit_card": "3530111333300000", "ip_address": "198.51.100.3",  "account_balance": 3100.25, "transaction_type": "refund",    "country": "PL"},
]

# ════════════════════════════════════════════════════════════════════════════════
# TAB 1 — Data Input & Intercept
# ════════════════════════════════════════════════════════════════════════════════
with tab1:
    col_left, col_right = st.columns([1.1, 1])

    with col_left:
        st.markdown("#### Raw Data Source")
        input_mode = st.radio("Input mode", ["Use sample dataset", "Paste JSON", "Upload JSON/CSV"], horizontal=True)

        raw_json_str = None
        uploaded_df  = None

        if input_mode == "Use sample dataset":
            st.caption(f"5 records · PII across email, phone, national_id, DOB, credit card, IP")
            st.dataframe(
                pd.DataFrame(SAMPLE_DATA),
                use_container_width=True, hide_index=True
            )
            raw_json_str = json.dumps(SAMPLE_DATA)

        elif input_mode == "Paste JSON":
            raw_json_str = st.text_area(
                "Paste JSON array", height=220,
                placeholder='[{"id":1,"email":"user@example.com","phone":"..."}]'
            )

        else:
            uploaded_file = st.file_uploader("Upload file", type=["json", "csv"])
            if uploaded_file:
                if uploaded_file.name.endswith(".csv"):
                    uploaded_df  = pd.read_csv(uploaded_file)
                    raw_json_str = uploaded_df.to_json(orient="records")
                else:
                    raw_json_str = uploaded_file.read().decode()

        st.divider()
        run_pipeline = st.button("🚀 Run Compliance Pipeline", type="primary", use_container_width=True)

    with col_right:
        st.markdown("#### Pipeline Stages")
        stages = [
            ("📥", "Intercept",  "Capture raw payload, checksum, source metadata"),
            ("🔍", "Audit",      "Detect PII, apply GDPR/PECA rules, flag violations"),
            ("🔐", "Encrypt",    "AES-256-GCM encrypt sensitive fields in-place"),
            ("📋", "Log",        "Write immutable structured audit trail"),
        ]
        for icon, name, desc in stages:
            st.markdown(f"""
            <div class="stage-box">
              <b>{icon} {name}</b><br>
              <span style='font-size:12px;color:#4a6fa5'>{desc}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("#### Engine")
        eng_col1, eng_col2 = st.columns(2)
        with eng_col1:
            st.metric("Engine", engine_choice.split()[0])
        with eng_col2:
            st.metric("Frameworks", ("GDPR " if enable_gdpr else "") + ("PECA" if enable_peca else ""))

    # ── Run pipeline ────────────────────────────────────────────────────────────
    if run_pipeline and raw_json_str:
        try:
            data = json.loads(raw_json_str)
        except Exception:
            st.error("❌ Invalid JSON. Please check your input.")
            st.stop()

        progress = st.progress(0, text="Initialising pipeline…")
        status   = st.empty()

        logger    = ComplianceLogger()
        interceptor = DataInterceptor()
        auditor   = ComplianceAuditor(
            frameworks=([f for f, e in [("GDPR", enable_gdpr), ("PECA", enable_peca)] if e]),
            pii_fields=pii_fields
        )
        encryptor = st.session_state.encryptor

        # Stage 1 — Intercept
        status.info("📥 Stage 1/4 · Intercepting raw data…")
        progress.progress(10)
        time.sleep(0.5)
        intercepted = interceptor.intercept(data)
        logger.log("INFO", "INTERCEPT", f"Captured {len(data)} records", {"engine": engine_choice, "checksum": intercepted["checksum"]})
        progress.progress(30)

        # Stage 2 — Audit
        status.warning("🔍 Stage 2/4 · Running compliance audit…")
        time.sleep(0.6)
        audit_results = auditor.audit(intercepted["records"])
        for rec in audit_results:
            for v in rec.get("violations", []):
                logger.log("WARN", "AUDIT", f"[Rec {rec['id']}] {v['framework']} violation: {v['field']} – {v['rule']}", rec)
            if rec.get("status") == "COMPLIANT":
                logger.log("INFO", "AUDIT", f"[Rec {rec['id']}] Passed all checks", {})
        progress.progress(55)

        # Stage 3 — Encrypt
        status.info("🔐 Stage 3/4 · Encrypting sensitive fields…")
        time.sleep(0.6)
        encrypted_data = encryptor.encrypt_records(audit_results, pii_fields)
        for rec in encrypted_data:
            logger.log("ENCRYPT", "ENCRYPT", f"[Rec {rec['id']}] Fields encrypted: {', '.join(pii_fields)}", {"algo": enc_algo})
        progress.progress(80)

        # Stage 4 — Finalise log
        status.info("📋 Stage 4/4 · Writing audit log…")
        time.sleep(0.4)
        logger.log("INFO", "PIPELINE", "Pipeline completed successfully",
                   {"total": len(data),
                    "violations": sum(len(r.get("violations", [])) for r in audit_results),
                    "encrypted_fields": len(pii_fields)})
        progress.progress(100)
        time.sleep(0.3)

        st.session_state.raw_data      = data
        st.session_state.audit_results = audit_results
        st.session_state.encrypted_data= encrypted_data
        st.session_state.audit_logs    = logger.get_logs()
        st.session_state.pipeline_ran  = True

        status.success(f"✅ Pipeline complete — {len(data)} records processed")
        progress.empty()

    elif run_pipeline:
        st.warning("⚠️ No data provided. Select a sample or paste JSON.")

# ════════════════════════════════════════════════════════════════════════════════
# TAB 2 — Compliance Audit
# ════════════════════════════════════════════════════════════════════════════════
with tab2:
    if not st.session_state.pipeline_ran:
        st.info("Run the pipeline from the **Data Input** tab first.")
    else:
        results = st.session_state.audit_results
        total       = len(results)
        violations  = [r for r in results if r.get("status") == "VIOLATION"]
        warnings_   = [r for r in results if r.get("status") == "WARNING"]
        compliant   = [r for r in results if r.get("status") == "COMPLIANT"]

        # Metrics row
        m1, m2, m3, m4 = st.columns(4)
        m1.markdown(f'<div class="metric-card"><div class="metric-value">{total}</div><div class="metric-label">Records Audited</div></div>', unsafe_allow_html=True)
        m2.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#ff5252">{len(violations)}</div><div class="metric-label">Violations</div></div>', unsafe_allow_html=True)
        m3.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#ffd600">{len(warnings_)}</div><div class="metric-label">Warnings</div></div>', unsafe_allow_html=True)
        m4.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#00e676">{len(compliant)}</div><div class="metric-label">Compliant</div></div>', unsafe_allow_html=True)

        st.divider()

        # Per-record detail
        for rec in results:
            status = rec.get("status", "UNKNOWN")
            badge  = {
                "VIOLATION": '<span class="badge-violation">VIOLATION</span>',
                "WARNING":   '<span class="badge-warning">WARNING</span>',
                "COMPLIANT": '<span class="badge-compliant">COMPLIANT</span>',
            }.get(status, status)

            with st.expander(f"Record #{rec['id']}  ·  {rec.get('name','—')}  ·  {badge}", expanded=(status == "VIOLATION")):
                cols = st.columns([1, 2])
                with cols[0]:
                    st.markdown("**PII Fields Detected**")
                    for field in rec.get("pii_detected", []):
                        st.markdown(f"- `{field}`")
                with cols[1]:
                    st.markdown("**Violations / Findings**")
                    viols = rec.get("violations", [])
                    if not viols:
                        st.success("No violations found")
                    else:
                        for v in viols:
                            st.error(f"**{v['framework']}** · `{v['field']}` — {v['rule']}")
                            st.caption(f"Risk: **{v['risk']}** · Article: {v['article']}")

        # Violation breakdown table
        if violations:
            st.divider()
            st.markdown("#### Violation Summary")
            rows = []
            for rec in violations:
                for v in rec.get("violations", []):
                    rows.append({"Record ID": rec["id"], "Name": rec.get("name"), "Framework": v["framework"],
                                 "Field": v["field"], "Rule": v["rule"], "Risk": v["risk"], "Article": v["article"]})
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ════════════════════════════════════════════════════════════════════════════════
# TAB 3 — Encryption
# ════════════════════════════════════════════════════════════════════════════════
with tab3:
    if not st.session_state.pipeline_ran:
        st.info("Run the pipeline from the **Data Input** tab first.")
    else:
        enc_data = st.session_state.encrypted_data
        encryptor = st.session_state.encryptor

        st.markdown(f"#### Encryption Summary · `{enc_algo}`")
        e1, e2, e3 = st.columns(3)
        e1.metric("Records Encrypted", len(enc_data))
        e2.metric("Fields per Record",  len(pii_fields))
        e3.metric("Total Encrypted Values", len(enc_data) * len(pii_fields))

        st.markdown(f"**Key ID:** `{encryptor.key_id}`")
        st.markdown(f"**Generated:** `{encryptor.key_created}`")

        st.divider()
        st.markdown("#### Encrypted Records")
        st.caption("Sensitive fields replaced with ciphertext (AES-GCM encrypted, base64-encoded)")

        for rec in enc_data:
            with st.expander(f"Record #{rec['id']}  ·  {rec.get('original_name', '—')}"):
                rows = []
                for k, v in rec.items():
                    if k in ("id", "original_name"): continue
                    is_enc  = isinstance(v, str) and v.startswith("ENC:")
                    display = ("●●●●●●●●●●●●" if mask_display else v) if is_enc else v
                    badge   = "🔐 encrypted" if is_enc else "🔓 plaintext"
                    rows.append({"Field": k, "Value": display, "Status": badge})
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        st.divider()
        st.markdown("#### Key Management Info")
        st.code(f"""
Key Algorithm : {enc_algo}
Key ID        : {encryptor.key_id}
Created       : {encryptor.key_created}
Rotation      : 90 days (policy)
Storage       : Azure Key Vault / HSM (recommended)
Scope         : Per-pipeline session key (demo mode)
        """, language="text")

# ════════════════════════════════════════════════════════════════════════════════
# TAB 4 — Audit Logs
# ════════════════════════════════════════════════════════════════════════════════
with tab4:
    if not st.session_state.pipeline_ran:
        st.info("Run the pipeline from the **Data Input** tab first.")
    else:
        logs = st.session_state.audit_logs

        l1, l2, l3 = st.columns(3)
        l1.metric("Total Log Entries", len(logs))
        l2.metric("Errors / Violations", sum(1 for l in logs if l["level"] in ("ERROR","WARN")))
        l3.metric("Encrypt Events",      sum(1 for l in logs if l["level"] == "ENCRYPT"))

        st.divider()
        st.markdown("#### Live Audit Console")

        level_colors = {"INFO": "log-info", "WARN": "log-warn", "ERROR": "log-error",
                        "SUCCESS": "log-success", "ENCRYPT": "log-encrypt"}
        console_html = '<div class="log-console">'
        for entry in logs:
            cls = level_colors.get(entry["level"], "log-info")
            ts  = entry["timestamp"]
            console_html += (
                f'<div class="{cls}">'
                f'[{ts}] [{entry["level"]:7s}] [{entry["stage"]:8s}] {entry["message"]}'
                f'</div>'
            )
        console_html += '</div>'
        st.markdown(console_html, unsafe_allow_html=True)

        st.divider()
        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            log_json = json.dumps(logs, indent=2)
            st.download_button(
                "⬇ Download Audit Log (JSON)",
                data=log_json,
                file_name=f"compliance_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        with col_dl2:
            log_df  = pd.DataFrame(logs)
            log_csv = log_df.drop(columns=["metadata"], errors="ignore").to_csv(index=False)
            st.download_button(
                "⬇ Download Audit Log (CSV)",
                data=log_csv,
                file_name=f"compliance_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

        st.divider()
        st.markdown("#### Structured Log Viewer")
        display_df = pd.DataFrame(logs)[["timestamp","level","stage","message"]]
        st.dataframe(display_df, use_container_width=True, hide_index=True)
