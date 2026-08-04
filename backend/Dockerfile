FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

ARG INSTALL_QUANTUM=0
ARG INSTALL_BLOCKCHAIN=0

COPY requirements*.txt ./
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && if [ "$INSTALL_QUANTUM" = "1" ]; then pip install -r requirements-quantum.txt; fi \
    && if [ "$INSTALL_BLOCKCHAIN" = "1" ]; then pip install -r requirements-blockchain.txt; fi

COPY app ./app
COPY tests ./tests
COPY pytest.ini ./pytest.ini

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
