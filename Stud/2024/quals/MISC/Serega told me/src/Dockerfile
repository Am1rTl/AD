FROM python:3.9-slim

WORKDIR /app

EXPOSE 4444

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    apt-get install --yes socat && \
    adduser --disabled-password --gecos "" serega && \
    echo "serega:NJVBIDKusfjnedf" | chpasswd && \
    chmod u-s $(which passwd) && \
    chown serega:serega /app && \
    chmod u+rwx /app

USER serega

COPY --chown=serega:serega --chmod=500 task.py .
COPY --chown=serega:serega --chmod=400 questions.json .

CMD ["socat", "TCP4-LISTEN:4444,reuseaddr,fork,keepalive", "SYSTEM:'python3 task.py',pty,echo=0,end-close,rawer,stderr"]
