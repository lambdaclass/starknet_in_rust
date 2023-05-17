#!/bin/bash

set -eu

address=$1

curl localhost:5050/mint \
    -H "Content-Type: application/json" \
    -d "{ \"address\": \"$address\", \"amount\": 9999999999999999999999999999, \"lite\": false }"