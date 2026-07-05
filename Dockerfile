FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
# - libfreetype6, libfontconfig1: matplotlib font rendering
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential libfreetype6 libfontconfig1 libpango-1.0-0 libpangoft2-1.0-0 && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements-equity.txt .
RUN pip install --no-cache-dir -r requirements-equity.txt && \
    apt-get purge -y --auto-remove build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

EXPOSE 8001

CMD ["sh", "-c", "uvicorn finrobot_equity.web_app.main:app --host 0.0.0.0 --port ${PORT:-8001}"]
