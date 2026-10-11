#!/bin/sh
# Deployment-only key injection; no new wire fields or cryptographic processing.
set +x
set -eu
ulimit -c 0
if [ -n "${PALLASYNC_RELAY_SIGNING_SEED_FILE:-}" ]; then
    if [ -n "${PALLASYNC_RELAY_SIGNING_SEED:-}" ]; then
        echo 'Choose exactly one relay key input' >&2
        exit 1
    fi
    seed_file=$PALLASYNC_RELAY_SIGNING_SEED_FILE
    umask 077
    : > "${seed_file}.waiting"
    while [ ! -f "$seed_file" ]; do sleep 1; done
    PALLASYNC_RELAY_SIGNING_SEED=$(cat "$seed_file")
    rm -f "$seed_file" "${seed_file}.waiting"
    export PALLASYNC_RELAY_SIGNING_SEED
    unset seed_file
elif [ -z "${PALLASYNC_RELAY_SIGNING_SEED:-}" ]; then
    echo 'Protected relay key input is required' >&2
    exit 1
fi
exec /usr/local/bin/pallasync-server
