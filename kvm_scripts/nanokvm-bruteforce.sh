#!/bin/sh
set -xe

FIFO_FILE="$(mktemp -d)"/commands.fifo
KVM_API="https://localhost:8080/api"

mkfifo "$FIFO_FILE"
ssh sect-nanokvm /bin/sh <"$FIFO_FILE" &

token="$(
	curl -sSk "$KVM_API/auth/login" \
	     -X POST \
	     -H 'Content-Type: application/json' \
	     --data-raw '{"username":"admin","password":"U2FsdGVkX18XhvPnZ31%2F1%2FQxU3l3aogCgJyhQYCdhbA%3D"}' \
	| jq -r .data.token
)"

curl -sSk "$KVM_API/stream/mjpeg" -H "Cookie: nano-kvm-token=$token" \
| ./nanokvm-bruteforce.py "$FIFO_FILE"
#| mpv -

# TODO: this won't execute. needs a SIGINT trap
rm "$FIFO_FILE"
rmdir "$(dirname "$FIFO_FILE")"
