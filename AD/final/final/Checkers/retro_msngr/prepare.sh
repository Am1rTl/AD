#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

apt update
apt install -y python3 python3-pip python3-virtualenv python3-setuptools
cd "$DIR" || exit
python3 -m virtualenv --python=python3 env
source env/bin/activate
pip3 install -r requirements.txt