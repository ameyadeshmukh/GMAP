FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    nmap \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN curl -fsSL https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_amd64.zip -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip httpx -d /usr/local/bin \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip

RUN curl -fsSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

COPY . .

CMD ["sh", "-c", "nmap --version && httpx -version && nuclei -version && celery -A backend.celery_app worker --loglevel=info"]
