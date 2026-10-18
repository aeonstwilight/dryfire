#!/usr/bin/env bash
# Start or stop the two query engines used by `make validate`.
#
#   scripts/engines.sh up     start Splunk and the Kusto emulator, wait until both answer
#   scripts/engines.sh down   stop and remove both containers
#
# Both run locally in Docker, with no accounts or cloud resources. Starting them
# accepts their licence terms (owner decision, 2026-10-18):
#   - Splunk Enterprise: --accept-license and the Splunk General Terms (needed for 10.x)
#   - Kusto emulator: ACCEPT_EULA=Y (Microsoft Software License Terms)
#
# The Splunk admin password and HEC token are random for each run and only exist
# inside the container and in build/validate/engines.env, which
# tests/run_validate.py reads. build/ is gitignored.

set -euo pipefail

# Images are pinned by digest so a re-tagged image can't change what runs.
# Splunk 10.6.0 (Docker Hub, published 2026-10-01).
SPLUNK_IMAGE="splunk/splunk:10.6.0@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4"
# Kusto emulator, weekly production build of 2026-09-25 (mcr.microsoft.com).
KUSTO_IMAGE="mcr.microsoft.com/azuredataexplorer/kustainer-linux:2026.09.25.1529-2637-33fff1a-weeklyproduction@sha256:a9b898ece7f5df341abf230e88be642bd8822e35af939443cabde9a6e0daf175"

ENV_FILE="build/validate/engines.env"

splunk_ready() {
    # The image's own health check passes only once its start-up (app install and
    # any restart that needs) has finished; then the API and HEC must answer.
    [ "$(docker inspect -f '{{.State.Health.Status}}' dryfire-splunk 2>/dev/null)" = "healthy" ] \
        && curl -sk -o /dev/null -w '%{http_code}' -u "admin:$password" https://localhost:8089/services/server/info | grep -q 200 \
        && curl -sk -o /dev/null -w '%{http_code}' https://localhost:8088/services/collector/health | grep -q 200
}

kusto_ready() {
    curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:8080/v1/rest/mgmt \
        -H 'Content-Type: application/json' -d '{"db":"NetDefaultDB","csl":".show version"}' | grep -q 200
}

wait_for() {
    local name="$1" check="$2"
    echo -n "Waiting for $name"
    for _ in $(seq 1 60); do
        if "$check"; then echo " ready"; return 0; fi
        echo -n "."; sleep 5
    done
    echo " not ready after 5 minutes"
    docker logs --tail 30 dryfire-splunk 2>&1 || true
    docker logs --tail 30 dryfire-kusto 2>&1 || true
    exit 1
}

up() {
    mkdir -p "$(dirname "$ENV_FILE")"
    password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
    hec_token="$(python3 -c 'import uuid; print(uuid.uuid4())')"

    docker rm -f dryfire-splunk dryfire-kusto >/dev/null 2>&1 || true

    echo "Starting Splunk ($SPLUNK_IMAGE)"
    # Our small Splunk app (index and sourcetype settings for the test events) is
    # packaged and installed by the image at start-up through SPLUNK_APPS_URL.
    tar -czf build/validate/dryfire_validate.tgz -C tests/validate/splunk_app dryfire_validate
    docker run -d --name dryfire-splunk --memory 6g \
        -p 8089:8089 -p 8088:8088 \
        -e SPLUNK_START_ARGS=--accept-license \
        -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
        -e SPLUNK_PASSWORD="$password" \
        -e SPLUNK_HEC_TOKEN="$hec_token" \
        -e SPLUNK_APPS_URL=/tmp/dryfire_validate.tgz \
        -v "$PWD/build/validate/dryfire_validate.tgz:/tmp/dryfire_validate.tgz:ro" \
        "$SPLUNK_IMAGE" >/dev/null

    echo "Starting the Kusto emulator ($KUSTO_IMAGE)"
    docker run -d --name dryfire-kusto --memory 4g \
        -p 8080:8080 \
        -e ACCEPT_EULA=Y \
        "$KUSTO_IMAGE" >/dev/null

    cat > "$ENV_FILE" <<EOF
SPLUNK_PASSWORD=$password
SPLUNK_HEC_TOKEN=$hec_token
EOF

    # Wait up to 5 minutes for each engine to answer; fail if one never does.
    wait_for "Splunk" splunk_ready
    wait_for "the Kusto emulator" kusto_ready
}

down() {
    docker rm -f dryfire-splunk dryfire-kusto >/dev/null 2>&1 || true
    rm -f "$ENV_FILE"
    echo "Stopped both engines."
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
