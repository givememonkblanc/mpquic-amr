#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=mp-uploader.local" -days 365
echo "certs/cert.pem, certs/key.pem 생성 완료"
