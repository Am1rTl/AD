FROM python:3.9-alpine
RUN apk update && apk add openssl sqlite
WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt
RUN mkdir keys &&  \
    openssl genrsa -out keys/private.pem 2048 && \
    openssl rsa -in keys/private.pem -out keys/public.pem -RSAPublicKey_out
COPY . .
ENTRYPOINT python3 main.py