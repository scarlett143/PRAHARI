FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

ARG INSTALL_QUANTUM=0
ARG INSTALL_BLOCKCHAIN=0
# Constant-time ML-KEM. Required for ENVIRONMENT=production, which now refuses to start
# on the pure-Python backend rather than warning about it. Off by default so a demo
# build stays fast and needs no compiler.
ARG INSTALL_LIBOQS=0

COPY requirements*.txt ./
# liboqs-python builds the native library from source, so the toolchain is installed
# only for that build and removed again to keep the runtime image small.
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && if [ "$INSTALL_QUANTUM" = "1" ]; then pip install -r requirements-quantum.txt; fi \
    && if [ "$INSTALL_BLOCKCHAIN" = "1" ]; then pip install -r requirements-blockchain.txt; fi \
    && if [ "$INSTALL_LIBOQS" = "1" ]; then \
         apt-get update \
         && apt-get install -y --no-install-recommends build-essential cmake ninja-build git \
         && pip install -r requirements-hardened.txt \
         && apt-get purge -y build-essential cmake ninja-build git \
         && apt-get autoremove -y \
         && rm -rf /var/lib/apt/lists/*; \
       fi

COPY app ./app
COPY tests ./tests
COPY pytest.ini ./pytest.ini

RUN useradd --create-home --uid 10001 prahari && chown -R prahari:prahari /app
USER prahari

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status==200 else 1)"

# --proxy-headers so client IPs in the audit log are the real ones behind a proxy.
# Workers stay at 1: the WebSocket connection registry is per-process, so a
# fan-out from one worker would not reach clients attached to another. Scale out
# with a shared broker (Redis pub/sub) before raising this.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--workers", "1"]
