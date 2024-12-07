FROM postgres:14-alpine

COPY ./docker/postgres.conf /etc/postgresql/postgresql.conf