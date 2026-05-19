# ── ComplianceShield Pipeline · Docker Image ───────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="ComplianceShield"
LABEL description="PECA/GDPR Compliance Data Pipeline — Streamlit UI"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py .
COPY pipeline/ pipeline/

# Streamlit config
RUN mkdir -p /root/.streamlit
RUN echo '[server]\nheadless = true\nport = 8501\n[browser]\ngatherUsageStats = false\n' \
    > /root/.streamlit/config.toml

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
