# On-aircraft (or companion-computer) agent.
#
# The image carries the backend's crypto package so the aircraft runs the exact
# primitives the server test suite exercises, rather than a second implementation
# that could drift from the protocol.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PRAHARI_BACKEND_PATH=/opt/prahari-backend \
    PRAHARI_KEYSTORE=/keystore/uav-keystore.json

WORKDIR /app

COPY bridge/requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Only the crypto primitives are needed; no API, database, or server code.
COPY backend/app/__init__.py /opt/prahari-backend/app/__init__.py
COPY backend/app/crypto /opt/prahari-backend/app/crypto

COPY bridge/prahari_bridge ./prahari_bridge

# Private keys are generated on first run and must survive a restart.
VOLUME ["/keystore"]

RUN useradd --create-home --uid 10001 bridge \
    && mkdir -p /keystore && chown -R bridge:bridge /keystore /app
USER bridge

ENTRYPOINT ["python", "-m", "prahari_bridge"]
CMD ["--source", "synthetic"]
