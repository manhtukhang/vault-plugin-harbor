#!/usr/bin/env bash
# Register ./bin/vault-plugin-harbor in the kind Vault and enable (or upgrade) the mount.
# Usage: scripts/plugin-register.sh <version>
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require vault jq kubectl sha256sum

version="${1:?usage: $0 <version>}"
bin="${ROOT_DIR}/bin/${PLUGIN_NAME}"
[[ -x "${bin}" ]] || die "${bin} not found; run make build"
[[ -s "${VAULT_INIT_FILE}" ]] || die "${VAULT_INIT_FILE} not found; run make kind-up"
vault_env

sha="$(sha256sum "${bin}" | cut -d' ' -f1)"
pod_sha="$(k -n "${VAULT_K8S_NAMESPACE}" exec vault-0 -c vault -- sha256sum "/vault/plugins/${PLUGIN_NAME}" | cut -d' ' -f1)"
# The bind mount pins the ./bin directory inode: if bin/ was deleted and recreated, the pod sees the old one.
[[ "${sha}" == "${pod_sha}" ]] || die "plugin binary in the Vault pod differs from ${bin}; recreate the cluster if bin/ was removed"

log "registering ${PLUGIN_NAME} ${version} (sha256 ${sha})"
vault plugin register -sha256="${sha}" -version="${version}" secret "${PLUGIN_NAME}"

if vault secrets list -format=json | jq -e --arg p "${PLUGIN_MOUNT}/" 'has($p)' >/dev/null; then
  log "upgrading mount ${PLUGIN_MOUNT}/ to ${version}"
  vault secrets tune -plugin-version="${version}" "${PLUGIN_MOUNT}/"
  vault plugin reload -type=secret -plugin="${PLUGIN_NAME}"
else
  log "enabling mount ${PLUGIN_MOUNT}/"
  vault secrets enable -path="${PLUGIN_MOUNT}" -plugin-version="${version}" "${PLUGIN_NAME}"
fi

# Test fixtures for the mount. Seeded here rather than in kind-up.sh: the mount only exists once
# the plugin is registered. Writing a role replaces only the fields sent, so a re-run converges.
seed_config() {
  local name secret
  [[ -s "${ENV_FILE}" ]] || die "${ENV_FILE} not found; run make kind-up"
  # Read in a subshell: the env file also carries the VAULT_* settings vault_env has pinned.
  # shellcheck source=/dev/null
  name="$(. "${ENV_FILE}" && printf '%s' "${HARBOR_ROBOT_NAME}")"
  # shellcheck source=/dev/null
  secret="$(. "${ENV_FILE}" && printf '%s' "${HARBOR_ROBOT_SECRET}")"

  log "writing the mount configuration"
  # Vault reaches Harbor from inside the cluster. allow_all_projects is the mount ceiling for the
  # role field of the same name, without which the ci-push-all fixture cannot be written.
  vault write "${PLUGIN_MOUNT}/config" \
    url="${HARBOR_INCLUSTER_URL}" \
    username="${name}" \
    password="${secret}" \
    ca_cert=@"${CA_CERT}" \
    allow_all_projects=true >/dev/null
}

seed_roles() {
  local spec name role
  # The namespace is a real project, so it tracks HARBOR_TEST_PROJECT instead of being duplicated.
  spec="$(sed "s/@TEST_PROJECT@/${HARBOR_TEST_PROJECT}/g" "${ROOT_DIR}/testdata/vault-roles.json")"
  while read -r name; do
    role="$(jq --arg n "${name}" '.[$n]' <<<"${spec}")"
    log "writing role ${name}"
    # ci-push stores push without pull on purpose: the plugin derives the implicit pull at mint
    # time, and a fixture that pre-added it would never exercise that path.
    vault write "${PLUGIN_MOUNT}/roles/${name}" \
      ttl="$(jq -r .ttl <<<"${role}")" \
      max_ttl="$(jq -r .max_ttl <<<"${role}")" \
      allow_all_projects="$(jq -r .allow_all_projects <<<"${role}")" \
      permissions="$(jq -c .permissions <<<"${role}")" >/dev/null
  done < <(jq -r 'keys[]' <<<"${spec}")
}

seed_config
seed_roles

vault secrets list -detailed -format=json |
  jq --arg p "${PLUGIN_MOUNT}/" '.[$p] | {type, plugin_version, running_plugin_version, running_sha256}'
