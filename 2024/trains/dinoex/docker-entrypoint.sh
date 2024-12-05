#!/usr/bin/env bash
set -e

rake db:rollback
rake db:create
rake db:migrate
rake db:seed

exec "$@"
