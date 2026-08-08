#!/bin/sh
# lnSwitchboard Cloudflare Mesh sidecar entrypoint wrapper.
#
# The cloudflare/mesh image reads MESH_NODE_TOKEN from the environment only,
# but lnSwitchboard provisions the node token AFTER the stack starts (there is
# no Docker socket access by design). Mirror the cloudflared --token-file
# pattern: exit until the app writes the token file, letting the compose
# restart policy re-enter until provisioning completes. Once started, supervise
# the real entrypoint so deleting or replacing the token file revokes the local
# connector even when only the lnSwitchboard application process restarts.
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

terminate_child() {
    kill -TERM "$CHILD_PID" 2>/dev/null || true
    wait "$CHILD_PID" 2>/dev/null || true
}

/entrypoint "$@" &
CHILD_PID=$!
trap 'terminate_child; exit 143' HUP INT TERM

while kill -0 "$CHILD_PID" 2>/dev/null; do
    sleep 2
    CURRENT_TOKEN="$(
        { sed -n 's/^MESH_NODE_TOKEN=//p' "$TOKEN_FILE" 2>/dev/null || true; } |
            tr -d '[:space:]'
    )"
    if [ "$CURRENT_TOKEN" != "$TOKEN" ]; then
        echo "mesh node authorization was withdrawn; stopping connector" >&2
        terminate_child
        exit 1
    fi
done

set +e
wait "$CHILD_PID"
STATUS=$?
set -e
exit "$STATUS"
