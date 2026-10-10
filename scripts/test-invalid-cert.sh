#!/bin/bash
cd "$(dirname "$0")/.."
bash scripts/test-9-untrusted-cert-handshake-failure.sh
