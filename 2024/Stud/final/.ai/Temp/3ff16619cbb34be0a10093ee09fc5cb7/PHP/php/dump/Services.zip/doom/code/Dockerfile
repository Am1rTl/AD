FROM ubuntu:22.04
RUN apt-get update && apt-get install libpq-dev socat sudo -yq \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /task
COPY ./doom .
COPY ./server.sh /
RUN chmod +x /server.sh doom
ENTRYPOINT /server.sh