FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    httpx \
    pyyaml \
    python-dotenv \
    pydantic \
    "pyats[full]" \
    genie

COPY app.py .

RUN mkdir -p /data

EXPOSE 8090

CMD ["python", "-u", "app.py"]
