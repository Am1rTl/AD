#!/bin/sh
cd ./src/
flask db upgrade
cd ../

exec "$@"
