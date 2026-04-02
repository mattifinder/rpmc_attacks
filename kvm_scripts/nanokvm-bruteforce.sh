#!/bin/sh
#
# To be executed on a different host.
#
# The nanokvm's 443 port needs to be forwarded to local 8080. For example with:
#
#ssh -N -L 8080:192.168.1.222:443 sect-proxy
#
# The ssh config should look something like this:
#
#     Host sect-proxy
#         Hostname tiger-experiments.sect.tu-berlin.de
#         User user
#         IdentityFile ~/.ssh/sect
#
#     Host sect-nanokvm
#         Hostname 192.168.1.222
#         User root
#         IdentityFile ~/.ssh/sect
#         ProxyJump sect-proxy
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
