# shellcheck shell=bash
# Shared settings for the local kind test environment. Sourced, not executed.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="vault-plugin-harbor"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
STATE_DIR="${ROOT_DIR}/tmp/kind"
KIND_KUBECONFIG="${STATE_DIR}/kubeconfig"
ENV_FILE="${STATE_DIR}/env.sh"
VAULT_INIT_FILE="${STATE_DIR}/vault-init.json"
CA_CERT="${STATE_DIR}/ca.pem"

HARBOR_CHART_REPO="https://helm.goharbor.io"
HARBOR_CHART_VERSION="1.19.2" # Harbor v2.15.2
VAULT_CHART_REPO="https://helm.releases.hashicorp.com"
VAULT_CHART_VERSION="0.34.1" # Vault 2.0.4, same chart as production

HARBOR_K8S_NAMESPACE="harbor"
VAULT_K8S_NAMESPACE="vault"
HARBOR_HOST_URL="https://localhost:30003"
# Absolute name: pods inherit the host DNS search domains, which Go tries before the bare name.
HARBOR_INCLUSTER_URL="https://harbor.${HARBOR_K8S_NAMESPACE}.svc.cluster.local."
VAULT_HOST_ADDR="http://127.0.0.1:30200"
HARBOR_ADMIN_USERNAME="admin"
HARBOR_ADMIN_PASSWORD="Harbor12345"
HARBOR_TEST_PROJECT="vault-plugin-harbor-test"
PLUGIN_NAME="vault-plugin-harbor"
PLUGIN_MOUNT="harbor"

log() { printf '==> %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}
require() {
  local c
  for c in "$@"; do
    command -v "${c}" >/dev/null 2>&1 || die "${c} not found in PATH"
  done
}

# Pin kubeconfig and context on every call: the ambient shell may point at a real cluster.
k() { kubectl --kubeconfig "${KIND_KUBECONFIG}" --context "${KUBE_CONTEXT}" "$@"; }
h() { helm --kubeconfig "${KIND_KUBECONFIG}" --kube-context "${KUBE_CONTEXT}" "$@"; }

cluster_exists() { kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; }

# Ambient VAULT_* settings (and ~/.vault-token via the token helper) could target or
# leak to another Vault, so every Vault call gets an explicit address and token.
vault_env() {
  unset VAULT_NAMESPACE VAULT_CACERT VAULT_CAPATH VAULT_CLIENT_CERT VAULT_CLIENT_KEY \
    VAULT_TLS_SERVER_NAME VAULT_AGENT_ADDR VAULT_PROXY_ADDR VAULT_HTTP_PROXY
  export VAULT_ADDR="${VAULT_HOST_ADDR}"
  VAULT_TOKEN="$(jq -r .root_token "${VAULT_INIT_FILE}")"
  export VAULT_TOKEN
}
