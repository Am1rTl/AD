#!/usr/bin/env bash

while true; do
    psql postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@db:5432/$POSTGRES_DB -c "DELETE FROM notes WHERE timestamp <= NOW() - INTERVAL '5 minutes'";
    psql postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@db:5432/$POSTGRES_DB -c "DELETE FROM players WHERE timestamp <= NOW() - INTERVAL '2 minutes'";
    sleep 60;
done