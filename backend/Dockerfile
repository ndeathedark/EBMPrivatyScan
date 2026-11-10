# Imagen del backend (API FastAPI + Chromium headless)
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Dependencias con versiones fijas y verificadas por hash (cadena de suministro)
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements.txt

# Chromium y sus bibliotecas del sistema, instaladas por Playwright para su versión exacta
RUN playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# Usuario sin privilegios: el navegador nunca se ejecuta como root
RUN useradd --system --uid 10001 --create-home --home-dir /home/app app \
    && mkdir -p /data && chown app:app /data

COPY --chown=app:app app ./app

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
