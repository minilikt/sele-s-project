FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Every dependency publishes wheels for this platform, so no compiler is needed.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --uid 10001 siem && chown -R siem:siem /app
USER siem

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).read()"

# Migrations run at startup (see migrations.upgrade_database), so an empty
# PostgreSQL volume is initialised automatically.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
