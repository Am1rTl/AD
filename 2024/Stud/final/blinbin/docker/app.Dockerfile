FROM python:3.9-slim

RUN apt-get -qq update
RUN pip install --upgrade pip && pip install pip-tools
RUN apt-get install -y --no-install-recommends --no-install-suggests  \
       curl \
       g++ \
       && rm -fr /var/lib/apt/lists/*
   
WORKDIR /app/

COPY requirements.txt .
RUN pip install --disable-pip-version-check --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7000

RUN chmod +x ./scripts/entry.sh
ENTRYPOINT ["./scripts/entry.sh"]