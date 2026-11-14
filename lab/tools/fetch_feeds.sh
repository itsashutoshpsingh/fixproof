#!/bin/bash
# Download the Trivy DB once into .cache/trivy; every scan then runs with --skip-db-update.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p .cache/trivy results/feeds
docker run --rm --name fp-trivy --memory 1g --network host -e HTTPS_PROXY \
  ${FIXPROOF_PROXY_CA:+-e SSL_CERT_FILE=/ca.crt -v "$FIXPROOF_PROXY_CA":/ca.crt:ro} \
  -v "$PWD/.cache/trivy":/cache mirror.gcr.io/aquasec/trivy:0.76.2 --cache-dir /cache image --download-db-only --no-progress
cp .cache/trivy/db/metadata.json results/feeds/trivy_db_metadata.json
sha256sum .cache/trivy/db/trivy.db | tee results/feeds/trivy_db.sha256
