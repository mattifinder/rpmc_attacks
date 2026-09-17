#!/usr/bin/env bash
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Christian Werling
# Copyright (c) 2026 Matti Finder
# Copyright (c) 2026 Hans Niklas Jacob
# Copyright (c) 2026 Julian Prein
# Copyright (c) 2026 Niclas Kühnapfel
# Copyright (c) 2026 Jean-Pierre Seifert

set -xe

cd "$(dirname "$(realpath "$0")")"

FIFO_FILE="$(mktemp -d)"/commands.fifo
KVM_API="https://localhost:8080/api"

token="$(
	curl -sSk "$KVM_API/auth/login" \
	     -X POST \
	     -H 'Content-Type: application/json' \
	     --data-raw '{"username":"admin","password":"U2FsdGVkX18XhvPnZ31%2F1%2FQxU3l3aogCgJyhQYCdhbA%3D"}' \
	| jq -r .data.token
)"

mkfifo "$FIFO_FILE"
echo "$FIFO_FILE"
ssh sect-nanokvm /bin/sh <"$FIFO_FILE" &
#cat "$FIFO_FILE" | tee >(sed 's/^/$ /')

# TODO: Uncomment when using the Hello OCR target
#       manual input
#curl -sSk "$KVM_API/stream/mjpeg" -H "Cookie: nano-kvm-token=$token" |
./nanokvm-bruteforce.py "$FIFO_FILE"

# TODO: this won't execute. needs a SIGINT trap
rm "$FIFO_FILE"
rmdir "$(dirname "$FIFO_FILE")"
