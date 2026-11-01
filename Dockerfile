FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm git curl unzip ffmpeg procps gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

VOLUME ["/data"]

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
RUN chmod 700 /app /app/main.py

CMD ["python3", "/app/main.py"]
