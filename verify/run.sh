#!/bin/bash

# 1. create input and output directories
if [ ! -d "input" ]; then
    mkdir -p input
fi

if [ ! -d "output" ]; then
    mkdir -p output
fi

# 2. check confidential.qcow2 and evidence.json
if [ ! -f "input/confidential.qcow2" ]; then
   echo "please put confidential.qcow2 file into input directory"
   exit 1
fi

if [ ! -f "input/evidence.json" ]; then
    echo "please put evidence.json file into input directory"
    exit 1
fi

# 3. build image
docker build -t tapp-verifier:latest -f Dockerfile.verifier .

# 4. start container
docker compose up -d

# 5. verify evidence
docker exec -it tapp-verifier /opt/verifier/entrypoint.sh

# 6. clean up
docker compose down
