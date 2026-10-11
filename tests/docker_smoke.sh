#!/usr/bin/env bash
# Linux Docker integration. age decryption and public DNS/TLS are replaced by explicit
# fixture adapters; the actual startup helper, signer, image, mounts and HTTP server run.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
fixture=$(mktemp -d)
state=$fixture/operator
project=pallasync-test-$$
dc() { docker compose --env-file /dev/null --project-name "$project" -f "$state/compose.generated.json" "$@"; }
cleanup() { dc down --volumes >/dev/null 2>&1 || true; rm -rf -- "$fixture"; }
trap cleanup EXIT
export PALLASYNC_TEST_REAL_CURL
PALLASYNC_TEST_REAL_CURL=$(command -v curl)
python3 - "$repo" "$state" "$fixture" "$project" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'tests'))
from test_docker_setup import config, profile, TEST_SEED
p = profile()
p.update(proxy=False, host_port=19300, project=sys.argv[4])
config.prepare(p, Path(sys.argv[2]))
fixture = Path(sys.argv[3])
(fixture / 'relay-seed.age').write_text('Public test fixture, not a protected production key', encoding='utf-8')
tools = fixture / 'tools'
tools.mkdir()
# The fixture seed is public and fixed; this adapter never reads a real age key.
(tools / 'age').write_text('#!/bin/sh\n[ "$1" = "--decrypt" ] || exit 1\nprintf %s ' + TEST_SEED.decode() + '\n', encoding='utf-8')
(tools / 'curl').write_text('''#!/usr/bin/env python3
import os, sys
args = [a.replace("https://relay.example.com/", "http://127.0.0.1:19300/") for a in sys.argv[1:]]
os.execv(os.environ["PALLASYNC_TEST_REAL_CURL"], ["curl", *args])
''', encoding='utf-8')
for file in tools.iterdir():
    file.chmod(0o755)
PY
fixture_seed() { python3 -c 'import base64; print(base64.urlsafe_b64encode(bytes([37])*32).rstrip(b"=").decode(), end="")'; }
fixture_seed | docker run --rm -i --network none --read-only --cap-drop ALL \
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$state,dst=/operator" \
    --entrypoint /usr/local/bin/pallasync-operator pallasync-server:local sign /operator/draft /operator/policy none
# Simulate a volume owned by the previous image UID; the real startup helper migrates it.
docker run --rm --network none --volume "${project}_pallasync-data:/data" \
    --user 0:0 --entrypoint /bin/sh pallasync-server:local \
    -eu -c 'printf persistent > /data/test-marker; chown -R 999:999 /data'
start() {
    PATH="$fixture/tools:$PATH" bash "$repo/scripts/setup-docker.sh" start \
        --state-dir "$state" --key-file "$fixture/relay-seed.age" --project "$project"
}
start > "$fixture/start-output"
container=$(dc ps --all --quiet pallasync)
docker inspect --format '{{json .Config.Env}}' "$container" > "$fixture/container-environment.json"
python3 - "$fixture" <<'PY'
import base64, json, sys
from pathlib import Path
f = Path(sys.argv[1])
assert all(not x.startswith('PALLASYNC_RELAY_SIGNING_SEED=') for x in json.loads((f / 'container-environment.json').read_bytes()))
assert base64.urlsafe_b64encode(bytes([37])*32).rstrip(b'=') not in (f / 'start-output').read_bytes()
PY
docker exec "$container" sh -eu -c 'test -s /data/pallasync.sqlite; test "$(cat /data/test-marker)" = persistent; test "$(stat -c %u /data/test-marker)" = 10001; test ! -e /run/pallasync/relay-seed'
dc restart pallasync
start
docker exec "$container" sh -eu -c 'test -s /data/pallasync.sqlite; test "$(cat /data/test-marker)" = persistent; test ! -e /run/pallasync/relay-seed'
echo 'Docker setup helper: policy publication, tmpfs unlock and persistent restart passed'
