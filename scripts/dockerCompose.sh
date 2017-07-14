#!/bin/bash
set -x
set -e
set -v

cp docker-compose.yml build/docker
cd build/docker
docker-compose up --build -d
