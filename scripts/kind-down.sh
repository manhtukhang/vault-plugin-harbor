#!/usr/bin/env bash
# Delete the local test environment and its generated state (certs, Vault keys, env file).
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require kind

if cluster_exists; then
  log "deleting kind cluster ${CLUSTER_NAME}"
  kind delete cluster --name "${CLUSTER_NAME}" --kubeconfig "${KIND_KUBECONFIG}"
fi
rm -rf "${STATE_DIR}"
