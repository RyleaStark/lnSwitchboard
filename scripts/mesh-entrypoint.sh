#!/bin/sh
# lnSwitchboard Cloudflare Mesh sidecar entrypoint wrapper.
#
# The cloudflare/mesh image reads MESH_NODE_TOKEN from the environment only,
# but lnSwitchboard provisions the node token AFTER the stack starts (there is
# no Docker socket access by design). Mirror the cloudflared --token-file
# pattern: exit until the app writes the token file, letting the compose
# restart policy re-enter until provisioning completes, then exec the real
# entrypoint with the token exported from the mounted file.
set -eu

TOKEN_FILE="${MESH_NODE_TOKEN_FILE:-/run/lnswitchboard/node.env}"

if [ ! -s "$TOKEN_FILE" ]; then
    echo "mesh node token not provisioned yet; waiting for lnSwitchboard" >&2
    exit 1
fi

TOKEN="$(sed -n 's/^MESH_NODE_TOKEN=//p' "$TOKEN_FILE" | tr -d '[:space:]')"
if [ -z "$TOKEN" ]; then
    echo "mesh node token file has no MESH_NODE_TOKEN entry yet" >&2
    exit 1
fi

export MESH_NODE_TOKEN="$TOKEN"
exec /entrypoint "$@"
