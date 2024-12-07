#!/bin/bash
socat TCP-LISTEN:666,fork,reuseaddr,bind=0.0.0.0 EXEC:"/task/doom"