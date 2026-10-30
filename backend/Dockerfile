FROM python:3.12-slim

WORKDIR /app

# System dependencies (Nmap + ClamAV client)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    clamdscan \
    libpq-dev \
    gcc \
    curl \
    # WeasyPrint dependencies
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libcairo2 \
    libgirepository1.0-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run unprivileged. Only the worker (raw sockets for nmap/scapy) overrides this in docker-compose.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin netaudit \
    && mkdir -p /app/scan_results /app/agent_files \
    && chown -R netaudit:netaudit /app
USER netaudit

# Default: run the API server
# --no-access-log: uvicorn logs the full URL, which would leak WebSocket ?token=<JWT>; nginx keeps the
# access log (path only).
# --proxy-headers: take the client IP from nginx's X-Forwarded-For. Safe because the
# API port is only reachable from the internal Docker network (nginx is the sole client).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-access-log"]
