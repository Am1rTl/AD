FROM python:3.9-slim

WORKDIR /app

EXPOSE 4444

ARG FLAG

ENV FLAG=$FLAG \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    apt-get install --yes socat && \
    adduser --disabled-password --gecos "" achilles && \
    echo "achilles:Z8GmrZtxFvt9GPvZ" | chpasswd && \
    chmod u-s $(which passwd) && \
    chown achilles:achilles /app && \
    chmod u+rwx /app

USER achilles

COPY --chown=achilles:achilles --chmod=500 achilles.py .

CMD ["socat", "TCP4-LISTEN:4444,reuseaddr,fork,keepalive", "SYSTEM:'python3 achilles.py',pty,echo=0,end-close,rawer,stderr"]
