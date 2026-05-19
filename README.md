# 🛡️ ComplianceShield — PECA/GDPR Data Pipeline

A production-grade **Streamlit application** that intercepts raw data, audits it
against **PECA 2016** (Pakistan Electronic Crimes Act) and **GDPR** compliance
frameworks, encrypts sensitive PII fields, and produces an immutable structured
audit log.

---

## Architecture

```
Raw Data Source
     │
     ▼
┌──────────────────────────────────────────────────────────┐
│  Stage 1 · INTERCEPT                                     │
│  DataInterceptor — SHA-256 checksum, batch ID, metadata  │
└──────────────────────────────────┬───────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────┐
│  Stage 2 · AUDIT (GDPR + PECA)                           │
│  ComplianceAuditor — PII detection, rule matching,       │
│  violation scoring, CRITICAL/HIGH/MEDIUM/LOW risk rating  │
└──────────────────────────────────┬───────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────┐
│  Stage 3 · ENCRYPT                                       │
│  DataEncryptor — AES-256-GCM (or Fernet / RSA-OAEP+AES) │
│  All PII fields replaced with ENC:<base64(nonce+ct+tag)> │
└──────────────────────────────────┬───────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────┐
│  Stage 4 · LOG                                           │
│  ComplianceLogger — append-only JSON structured log,     │
│  exportable as JSON Lines (SIEM) or CSV                  │
└──────────────────────────────────────────────────────────┘
```

---

## Compliance Frameworks

### GDPR
| Rule ID | Article | Field | Risk |
|---------|---------|-------|------|
| GDPR-ART25-001 | Art. 25 – Data Minimisation | national_id | HIGH |
| GDPR-ART32-001 | Art. 32 – Security of Processing | credit_card | CRITICAL |
| GDPR-ART35-001 | Art. 35 – DPIA Required | dob | MEDIUM |
| GDPR-ART5-001  | Art. 5 – Purpose Limitation | ip_address | MEDIUM |
| GDPR-ART5-002  | Art. 5 – Lawfulness | email | MEDIUM |

### PECA 2016
| Rule ID | Section | Field | Risk |
|---------|---------|-------|------|
| PECA-SEC14-001 | Sec. 14 – Identity Information | national_id | HIGH |
| PECA-SEC18-001 | Sec. 18 – Data Protection | phone | MEDIUM |
| PECA-SEC34-001 | Sec. 34 – Dignity/Privacy | dob | LOW |
| PECA-SEC14-002 | Sec. 14 – Identity Information | credit_card | CRITICAL |

---

## Encryption

| Algorithm | Key Size | Mode | Notes |
|-----------|----------|------|-------|
| AES-256-GCM | 256-bit | Authenticated | Default — recommended |
| Fernet (AES-128-CBC) | 128-bit | HMAC-SHA256 | Simple symmetric |
| RSA-OAEP + AES | 2048-bit RSA + 256-bit AES | Hybrid | Key wrapping |

Encrypted values format: `ENC:<base64(nonce + ciphertext + tag)>`

---

## Quick Start

### Local (Python)
```bash
pip install -r requirements.txt
streamlit run app.py
```

### Docker
```bash
docker compose up --build
# Open http://localhost:8501
```

### Docker (manual)
```bash
docker build -t complianceshield .
docker run -p 8501:8501 complianceshield
```

---

## Production Extensions

### Apache Spark
Replace `DataInterceptor.intercept()` with a PySpark job:
```python
spark = SparkSession.builder.appName("ComplianceShield").getOrCreate()
df = spark.read.json("s3a://raw-data/landing/")
df = df.rdd.mapPartitions(compliance_audit_udf).toDF()
df.write.format("delta").mode("append").save("s3a://processed/compliant/")
```

### Apache Airflow DAG
```python
from airflow import DAG
from airflow.operators.python import PythonOperator

with DAG("compliance_pipeline", schedule="@hourly") as dag:
    ingest   = PythonOperator(task_id="ingest",   python_callable=intercept)
    audit    = PythonOperator(task_id="audit",    python_callable=audit_records)
    encrypt  = PythonOperator(task_id="encrypt",  python_callable=encrypt_fields)
    log_task = PythonOperator(task_id="log",      python_callable=write_audit_log)
    ingest >> audit >> encrypt >> log_task
```

### Key Management (Production)
- Store AES keys in **Azure Key Vault** or **AWS KMS**
- Implement 90-day automatic key rotation
- Use **Hardware Security Modules (HSM)** for RSA private keys
- Log all key access events to the compliance audit trail

---

## File Structure
```
compliance_pipeline/
├── app.py                   # Streamlit UI
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
└── pipeline/
    ├── __init__.py                                                                            `                             
    ├── interceptor.py       # Stage 1: Data interception + checksums
    ├── auditor.py           # Stage 2: GDPR/PECA rule engine
    ├── encryptor.py         # Stage 3: AES-256-GCM encryption
    ├── logger.py            # Stage 4: Structured audit logging
    └── spark_engine.py      # Spark/Airflow execution simulation

```

<img width="1572" height="642" alt="Screenshot 2026-05-19 083230" src="https://github.com/user-attachments/assets/287eef0a-c3a4-45ce-abbe-211d28c3de59" />
<img width="1461" height="748" alt="Screenshot 2026-05-19 083215" src="https://github.com/user-attachments/assets/98fcb921-2575-4579-86bb-89ef3fee9e86" />
<img width="1447" height="880" alt="Screenshot 2026-05-19 083144" src="https://github.com/user-attachments/assets/45082ec0-4091-41b7-ba97-54ee95a0d6ad" />
<img width="1795" height="791" alt="Screenshot 2026-05-19 083048" src="https://github.com/user-attachments/assets/e5718d42-c7cf-4dd1-9885-2e5a9ff5233f" />
<img width="1561" height="695" alt="Screenshot 2026-05-19 083424" src="https://github.com/user-attachments/assets/7a1777bf-92ec-4036-b332-bd47f9a896ef" />
<img width="1515" height="811" alt="Screenshot 2026-05-19 083358" src="https://github.com/user-attachments/assets/f874f8f7-3ff4-4d51-bc11-6b8b51c41152" />
<img width="1493" height="797" alt="Screenshot 2026-05-19 083335" src="https://github.com/user-attachments/assets/58d4194a-7842-4079-8cc5-0c965422e481" />
<img width="1490" height="767" alt="Screenshot 2026-05-19 083309" src="https://github.com/user-attachments/assets/f5338a22-ef18-470c-be78-46daa4c6bc9f" />

