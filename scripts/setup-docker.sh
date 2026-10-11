#!/usr/bin/env bash
# Linux deployment helper. Secrets never enter Compose, arguments, or disk in plaintext.
set +x
set -euo pipefail
umask 077
ulimit -c 0

usage() {
    cat <<'EOF'
Usage: bash scripts/setup-docker.sh [setup|start|status|stop] [options]
  --origin https://api.yunfi.f5.si   Required for the first setup
  --state-dir PATH                 Default: $XDG_DATA_HOME/pallasync or ~/.local/share/pallasync
  --key-file PATH                  Default: $XDG_CONFIG_HOME/pallasync/relay-seed.age or ~/.config/pallasync/relay-seed.age
  --host-port PORT                 Default: 3090
  --host-bind ADDRESS              Default: 0.0.0.0 (preserve the existing upstream route)
  --no-proxy                       Use the existing HTTPS proxy (default)
  --with-proxy                     Opt in to an included Caddy HTTPS proxy
  --cloudflare                     Disclose an existing Cloudflare route; do not configure it
  --project NAME                   Default: pallasync (keep the same value to reuse data)
Requires Linux, Docker Engine + Compose v2, Python 3.10+, age, OpenSSL, curl, flock.
setup generates public documents, signs them, starts Docker and checks HTTPS.
start reuses the protected key and signed documents; unlock again after every restart.
stop stops containers without deleting data. status shows container health.
EOF
}
fail() { echo "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "Missing command: $1 (see docs/docker-setup.md)"; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
original_args=("$@")
action=setup
if [[ ${1:-} =~ ^(setup|start|status|stop)$ ]]; then action=$1; shift; fi
state_dir=${XDG_DATA_HOME:-$HOME/.local/share}/pallasync
key_file=${XDG_CONFIG_HOME:-$HOME/.config}/pallasync/relay-seed.age
origin= host_port=3090 host_bind=0.0.0.0 proxy=no project=pallasync cloudflare=no
while (($#)); do
    case $1 in
        --help|-h) usage; exit 0 ;;
        --origin|--state-dir|--key-file|--host-port|--host-bind|--project)
            (($# >= 2)) || fail "Missing value for $1"
            case $1 in
                --origin) origin=$2 ;; --state-dir) state_dir=$2 ;; --key-file) key_file=$2 ;;
                --host-port) host_port=$2 ;; --host-bind) host_bind=$2 ;; --project) project=$2 ;;
            esac
            shift 2 ;;
        --no-proxy) proxy=no; shift ;;
        --with-proxy) proxy=yes; shift ;;
        --cloudflare) cloudflare=yes; shift ;;
        *) fail "Unknown argument: $1" ;;
    esac
done
[[ $project =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail 'Invalid Compose project name'
need python3
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ is required")'
state_dir=$(python3 -c 'import sys; from pathlib import Path; print(Path(sys.argv[1]).expanduser().resolve())' "$state_dir")
key_file=$(python3 -c 'import sys; from pathlib import Path; print(Path(sys.argv[1]).expanduser().resolve())' "$key_file")
python3 - "$repo" "$state_dir" "$key_file" <<'PY'
import sys
from pathlib import Path
repo, state, key = map(Path, sys.argv[1:])
if state.is_relative_to(repo) or key.is_relative_to(repo) or key.is_relative_to(state):
    raise SystemExit('Keep deployment state and the protected key outside the repository; keep the key outside the public state directory')
PY
mkdir -p -- "$state_dir"
chmod 700 -- "$state_dir"
need flock
exec 9>"$state_dir/setup.lock"
flock -n 9 || fail 'Another setup command is running'
need docker
docker compose version >/dev/null
[[ $(docker info --format '{{.OSType}}') == linux ]] || fail 'Linux Docker Engine is required'
unset PALLASYNC_RELAY_SIGNING_SEED
# --env-file /dev/null keeps unrelated repository .env settings out of this setup.
dc() { docker compose --env-file /dev/null --project-name "$project" -f "$state_dir/compose.generated.json" "$@"; }
if [[ $action == status || $action == stop ]]; then
    [[ -f $state_dir/deployment.json ]] || fail 'Run setup first'
    if [[ $action == status ]]; then dc ps --all; else dc stop; fi
    exit 0
fi
need age; need openssl; need curl
if ! python3 "$repo/scripts/swap_guard.py"; then
    need systemd-run
    flock -u 9
    exec 9>&-
    exec systemd-run --user --scope --quiet -p MemorySwapMax=0 \
        bash "$repo/scripts/setup-docker.sh" "${original_args[@]}"
fi
if [[ $(wc -l < /proc/swaps) -gt 1 ]]; then
    daemon_pid=$(systemctl show docker.service --property MainPID --value)
    python3 "$repo/scripts/swap_guard.py" "$daemon_pid" || \
        fail 'Protect Docker daemon I/O before unlocking: sudo systemctl set-property docker.service MemorySwapMax=0'
fi
if [[ $action == setup ]]; then
    [[ -n $origin ]] || fail '--origin is required for setup'
    config_args=(--origin "$origin" --state-dir "$state_dir" --host-port "$host_port" --host-bind "$host_bind" --project "$project")
    [[ $proxy == no ]] || config_args+=(--with-proxy)
    [[ $cloudflare == no ]] || config_args+=(--cloudflare)
    python3 "$repo/scripts/docker_config.py" "${config_args[@]}"
    echo 'Building server and offline policy signer...'
    docker build --progress plain --tag pallasync-server:local "$repo"
else
    [[ -f $state_dir/deployment.json && -f $state_dir/policy/privacy.json ]] || fail 'Run setup first'
    docker image inspect pallasync-server:local >/dev/null
fi
# Read only public scalar configuration; never source generated operator text as shell code.
setting() { python3 -c 'import json,sys; p=json.load(open(sys.argv[1],encoding="utf-8")); v=p[sys.argv[2]]; print("none" if v is None else v)' "$state_dir/deployment.json" "$1"; }
configured_origin=$(setting origin)
[[ $(setting project) == "$project" ]] || fail 'Compose project differs from the existing deployment; keep the original project to reuse the data volume'
[[ -z $origin || $origin == "$configured_origin" ]] || fail 'Origin differs from the existing deployment'
origin=$configured_origin
quota=$(setting quota)
host_port=$(setting host_port)
key_tmp= seed= checks=
cleanup() {
    unset seed
    [[ -z $key_tmp ]] || rm -f -- "$key_tmp"
    [[ -z $checks ]] || rm -rf -- "$checks"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -d $state_dir/policy && ! -e $state_dir/policy/privacy.md && ! -e $state_dir/policy/privacy.json ]]; then
    rmdir -- "$state_dir/policy" || fail 'The unsigned policy directory contains files; refusing to replace them'
fi
if [[ ! -f $key_file ]]; then
    [[ ! -e $state_dir/policy ]] || fail 'The policy already pins a key. Restore the original protected key; do not generate a replacement automatically.'
    if docker volume inspect "${project}_pallasync-data" >/dev/null 2>&1; then
        fail 'An existing data volume may pin the original key. Restore that protected key before setup; no replacement is generated.'
    fi
    key_dir=$(dirname -- "$key_file")
    mkdir -p -- "$key_dir"
    chmod 700 -- "$key_dir"
    key_tmp=$(mktemp "$key_dir/.relay-seed.XXXXXX")
    echo 'Creating an independent relay key. Enter an age passphrase and keep it separately.'
    openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n' | age --passphrase --output "$key_tmp"
    # Atomic publication without overwriting an existing key, even under a concurrent creation.
    ln -- "$key_tmp" "$key_file"
    rm -f -- "$key_tmp"
    key_tmp=
    chmod 600 -- "$key_file"
fi
chmod 600 -- "$key_file"
echo 'Unlock the protected relay key for this invocation.'
seed=$(age --decrypt "$key_file") || fail 'Key unlock failed'
[[ $seed =~ ^[A-Za-z0-9_-]{43}$ ]] || fail 'Protected file does not contain a canonical 32-byte seed'
operator() {
    printf '%s' "$seed" | docker run --rm -i --network none --read-only --cap-drop ALL --memory 128m --memory-swap 128m \
        --security-opt no-new-privileges:true --ulimit core=0 \
        --user "$(id -u):$(id -g)" --mount "type=bind,src=$state_dir,dst=/operator" \
        --entrypoint /usr/local/bin/pallasync-operator pallasync-server:local "$@"
}
if [[ ! -e $state_dir/policy ]]; then
    if ! operator sign /operator/draft /operator/policy "$quota"; then
        # No published revision exists; allow corrected operator answers on the next setup.
        rm -f -- "$state_dir/deployment.json"
        fail 'Draft rejected. Run setup again to correct the public settings; the protected key is preserved.'
    fi
else
    operator verify /operator/policy "$quota"
fi
# Upgrade ownership of this project's dedicated data volume from older image UIDs.
# No network, policy, key, or host directory is mounted in this short-lived helper.
docker run --rm --network none --read-only --user 0:0 --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --security-opt no-new-privileges:true \
    --volume "${project}_pallasync-data:/data" --entrypoint /bin/sh pallasync-server:local \
    -eu -c 'chown -R --no-dereference 10001:10001 /data'
dc up --detach
container=$(dc ps --all --quiet pallasync)
[[ -n $container ]] || fail 'Relay container was not created'
unlocked=no
for ((i=0; i<60; i++)); do
    if docker exec "$container" test -f /run/pallasync/relay-seed.waiting 2>/dev/null; then
        printf '%s' "$seed" | docker exec -i "$container" sh -eu -c \
            'umask 077; cat > /run/pallasync/relay-seed.next; mv /run/pallasync/relay-seed.next /run/pallasync/relay-seed'
        unlocked=yes
        break
    fi
    if [[ $(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container") == healthy ]]; then
        unlocked=yes
        break
    fi
    sleep 1
done
unset seed
[[ $unlocked == yes ]] || fail 'Container did not reach key-unlock readiness; use status to inspect it'
# Compose 2.4 on existing deployments lacks --wait-timeout; inspect Engine health directly.
healthy=no
for ((i=0; i<60; i++)); do
    if [[ $(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container") == healthy ]]; then
        healthy=yes
        break
    fi
    sleep 1
done
[[ $healthy == yes ]] || fail 'Relay health did not become healthy within 60 seconds'
checks=$(mktemp -d)
curl --fail --silent --show-error --max-time 10 "http://127.0.0.1:$host_port/pallasync/v3/health" > "$checks/local-health.json"
echo "Checking public HTTPS, key pin and privacy documents at $origin..."
curl --tlsv1.2 --fail --silent --show-error --retry 12 --retry-delay 5 --retry-all-errors --connect-timeout 5 --max-time 10 \
    "$origin/pallasync/v3/health" > "$checks/health.json"
curl --tlsv1.2 --fail --silent --show-error --max-time 15 "$origin/privacy.md" > "$checks/privacy.md"
curl --tlsv1.2 --fail --silent --show-error --max-time 15 "$origin/privacy.json" > "$checks/privacy.json"
python3 - "$state_dir/policy" "$checks" "$origin" <<'PY'
import json, sys
from pathlib import Path
policy, checks = map(Path, sys.argv[1:3])
p = json.loads((policy / 'privacy.json').read_bytes())
for name in ['local-health.json', 'health.json']:
    h = json.loads((checks / name).read_bytes())
    if (h['protocol'] != 'pallasync/3' or h['relay_origin'] != sys.argv[3]
            or h['relay_key_id'] != p['relay_key_id'] or h['limits'] != p['limits']
            or h['relay_public_key'] != (policy / 'relay-public-key.txt').read_text().strip()):
        raise SystemExit('Health origin/key/limits mismatch')
if ((checks / 'privacy.md').read_bytes() != (policy / 'privacy.md').read_bytes()
        or json.loads((checks / 'privacy.json').read_bytes()) != p):
    raise SystemExit('Public policy mismatch')
PY
echo "Ready: $origin (pallasync/3). Public policies: $state_dir/policy"
echo 'After host/container restart, run this command with start to unlock the same key.'
