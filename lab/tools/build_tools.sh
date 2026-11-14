#!/bin/bash
# Build the two scanners that are not used from a container image, from the Go module proxy.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p .tools
docker run --rm --name fp-gobuild --memory 2g --cpus 2 --network host \
  -e HTTPS_PROXY -e https_proxy -e CGO_ENABLED=0 -e GOFLAGS=-trimpath -e GOTOOLCHAIN=auto -e GOEXPERIMENT=jsonv2 \
  ${FIXPROOF_PROXY_CA:+-e SSL_CERT_FILE=/ca.crt -v "$FIXPROOF_PROXY_CA":/ca.crt:ro} \
  -v "$PWD/.tools":/out mirror.gcr.io/library/golang:1.25-bookworm bash -c '
    export GOBIN=/out
    go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1
    go install github.com/future-architect/vuls/cmd/vuls@v0.42.0'
sha256sum .tools/osv-scanner .tools/vuls
