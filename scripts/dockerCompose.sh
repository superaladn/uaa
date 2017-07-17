#!/bin/bash
set -x
set -e
set -v

cd build/docker
docker-compose up --build -d
