FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake \
                                               gcc \
                                               build-essential \
                                               socat \
                                               libpq-dev \
                                               && \
    apt-get clean

RUN mkdir -p /var/tmp/dnser/build
WORKDIR /var/tmp/dnser/build

ENTRYPOINT cmake -DCMAKE_BUILD_TYPE=Debug ../; make; socat -v TCP4-LISTEN:1337,reuseaddr,fork,keepalive EXEC:./dnser
