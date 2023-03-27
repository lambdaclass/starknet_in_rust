#!/bin/sh

set -e
set -o pipefail

SCRIPT_DIR=$(dirname $0)

patch < ${SCRIPT_DIR}/move-devnet-sir.patch
