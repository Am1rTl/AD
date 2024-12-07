#!/usr/bin/env bash

cleanup() {
    echo "== CLEAN $(date -uR) =="
    psql postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@db:5432/$POSTGRES_DB -c "DELETE FROM users WHERE timestamp <= NOW() - INTERVAL '5 minutes'";
    psql postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@db:5432/$POSTGRES_DB -c "DELETE FROM balances WHERE timestamp <= NOW() - INTERVAL '3 minutes'";
    psql postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@db:5432/$POSTGRES_DB -c "DELETE FROM kopilkas WHERE timestamp <= NOW() - INTERVAL '3 minutes'";
    psql postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@db:5432/$POSTGRES_DB -c "DELETE FROM kopilkaMembers WHERE timestamp <= NOW() - INTERVAL '3 minutes'";

    find '/app/reports' -type f -and -not -newermt "-180 seconds" -delete
    find '/app/reports' -type d -not -newermt "-180 seconds" ! -path '/app/reports' -delete

    sleep 180;
}

while true; do cleanup; done &

frankenphp run -c '/app/Caddyfile'
