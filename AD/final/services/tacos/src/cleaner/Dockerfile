FROM ubuntu:24.04
RUN apt-get update && apt-get install postgresql-client -yqq \
  && rm -rf /var/lib/apt/lists/*

COPY --chmod=755 cleaner.sh /cleaner.sh

CMD ["/cleaner.sh"]