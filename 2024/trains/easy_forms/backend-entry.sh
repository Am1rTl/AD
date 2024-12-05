#!/bin/sh
set -e

if [ "${CACHE_ENABLED:-0}" -eq 1 ]; then
	echo "### Cache recreate  ###"
	php artisan cache:clear
	php artisan route:cache
	php artisan config:cache
fi

if [ "${1#-}" != "$1" ]; then
	set -- php "$@"
fi

exec "$@"