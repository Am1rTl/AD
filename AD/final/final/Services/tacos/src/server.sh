#!/bin/bash

socat TCP-LISTEN:1488,fork,reuseaddr,bind=0.0.0.0 EXEC:"env LD_PRELOAD=/service/libc.so.6 /service/tacos"
