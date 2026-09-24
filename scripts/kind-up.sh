#!/usr/bin/env bash
# Idempotently create the local test environment: kind cluster, Harbor (TLS), Vault
# (initialized and unsealed), and a least-privilege Harbor robot for the plugin.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require docker kind kubectl helm jq openssl curl

mkdir -p "${STATE_DIR}" "${ROOT_DIR}/bin"
chmod 700 "${STATE_DIR}"

create_cluster() {
  if cluster_exists; then
    log "kind cluster ${CLUSTER_NAME} already exists"
  else
    log "creating kind cluster ${CLUSTER_NAME}"
    sed "s#@PLUGIN_DIR@#${ROOT_DIR}/bin#" "${ROOT_DIR}/testdata/kind-config.yml" >"${STATE_DIR}/kind-config.yml"
    # --kubeconfig keeps kind from editing ~/.kube/config or switching the current context.
    kind create cluster --name "${CLUSTER_NAME}" --config "${STATE_DIR}/kind-config.yml" \
      --kubeconfig "${KIND_KUBECONFIG}" --wait 120s
  fi
  kind get kubeconfig --name "${CLUSTER_NAME}" >"${KIND_KUBECONFIG}.tmp"
  mv "${KIND_KUBECONFIG}.tmp" "${KIND_KUBECONFIG}"
  chmod 600 "${KIND_KUBECONFIG}"
}

generate_certs() {
  if [[ -s "${CA_CERT}" && -s "${STATE_DIR}/harbor.pem" && -s "${STATE_DIR}/harbor-key.pem" ]]; then
    return
  fi
  log "generating test CA and Harbor server certificate"
  local d="${STATE_DIR}"
  (
    umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=vault-plugin-harbor test CA" -keyout "${d}/ca-key.pem" -out "${d}/ca.pem" \
      -config <(printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -subj "/CN=harbor.${HARBOR_K8S_NAMESPACE}.svc.cluster.local" -keyout "${d}/harbor-key.pem" -out "${d}/harbor.csr" \
      -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n')
    openssl x509 -req -in "${d}/harbor.csr" -CA "${d}/ca.pem" -CAkey "${d}/ca-key.pem" \
      -set_serial "0x$(openssl rand -hex 16)" -days 825 -out "${d}/harbor.pem" \
      -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\nsubjectAltName=DNS:harbor,DNS:harbor.%s,DNS:harbor.%s.svc,DNS:harbor.%s.svc.cluster.local,DNS:localhost,IP:127.0.0.1\n' \
        "${HARBOR_K8S_NAMESPACE}" "${HARBOR_K8S_NAMESPACE}" "${HARBOR_K8S_NAMESPACE}")
    rm -f "${d}/harbor.csr"
  )
  chmod 644 "${CA_CERT}"
}

ensure_namespace() {
  k create namespace "$1" --dry-run=client -o yaml | k apply -f - >/dev/null
}

install_harbor() {
  log "installing Harbor chart ${HARBOR_CHART_VERSION}"
  ensure_namespace "${HARBOR_K8S_NAMESPACE}"
  k -n "${HARBOR_K8S_NAMESPACE}" create secret generic harbor-tls \
    --from-file=tls.crt="${STATE_DIR}/harbor.pem" \
    --from-file=tls.key="${STATE_DIR}/harbor-key.pem" \
    --from-file=ca.crt="${CA_CERT}" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  h upgrade --install harbor harbor --repo "${HARBOR_CHART_REPO}" --version "${HARBOR_CHART_VERSION}" \
    --namespace "${HARBOR_K8S_NAMESPACE}" --values "${ROOT_DIR}/testdata/harbor-values.yaml" \
    --wait --timeout 20m
}

install_vault() {
  log "installing Vault chart ${VAULT_CHART_VERSION}"
  ensure_namespace "${VAULT_K8S_NAMESPACE}"
  # No --wait: a sealed Vault never reports Ready.
  h upgrade --install vault vault --repo "${VAULT_CHART_REPO}" --version "${VAULT_CHART_VERSION}" \
    --namespace "${VAULT_K8S_NAMESPACE}" --values "${ROOT_DIR}/testdata/vault-values.yaml"
}

vault_api() {
  local method="$1" path="$2"
  shift 2
  curl -fsS -X "${method}" "${VAULT_HOST_ADDR}/v1/${path}" "$@"
}

init_vault() {
  log "waiting for the Vault API"
  local i
  for i in $(seq 1 120); do
    vault_api GET sys/seal-status >/dev/null 2>&1 && break
    [[ ${i} -eq 120 ]] && die "Vault API not reachable at ${VAULT_HOST_ADDR}"
    sleep 5
  done

  local status
  status="$(vault_api GET sys/seal-status)"
  if [[ "$(jq -r .initialized <<<"${status}")" != "true" ]]; then
    log "initializing Vault (1 key share)"
    (
      umask 077
      vault_api PUT sys/init --data '{"secret_shares":1,"secret_threshold":1}' >"${VAULT_INIT_FILE}.tmp"
      mv "${VAULT_INIT_FILE}.tmp" "${VAULT_INIT_FILE}"
    )
    status="$(vault_api GET sys/seal-status)"
  fi
  [[ -s "${VAULT_INIT_FILE}" ]] || die "Vault is initialized but ${VAULT_INIT_FILE} is missing; run make kind-down && make kind-up"

  if [[ "$(jq -r .sealed <<<"${status}")" == "true" ]]; then
    log "unsealing Vault"
    jq '{key: .keys_base64[0]}' "${VAULT_INIT_FILE}" | vault_api PUT sys/unseal --data @- >/dev/null
  fi

  for i in $(seq 1 60); do
    # sys/health returns 200 only on an unsealed, active node.
    vault_api GET sys/health >/dev/null 2>&1 && return
    sleep 2
  done
  die "Vault did not become active"
}

harbor_api() {
  curl -fsS --cacert "${CA_CERT}" -H 'Content-Type: application/json' "$@"
}
harbor_admin() {
  harbor_api -K <(printf 'user = "%s:%s"\n' "${HARBOR_ADMIN_USERNAME}" "${HARBOR_ADMIN_PASSWORD}") "$@"
}
harbor_as() {
  harbor_api -K <(printf 'user = "%s:%s"\n' "$1" "$2") "${@:3}"
}

# Prints the system robot named robot$<name> as JSON, or nothing.
find_system_robot() {
  local name="$1" page=1 robots
  while :; do
    robots="$(harbor_admin "${HARBOR_HOST_URL}/api/v2.0/robots?q=Level%3Dsystem&page=${page}&page_size=100")"
    jq -e --arg n "robot\$${name}" '.[] | select(.name == $n)' <<<"${robots}" && return
    [[ "$(jq length <<<"${robots}")" -lt 100 ]] && return
    page=$((page + 1))
  done
}

normalize_permissions() {
  jq -S '[.permissions[] | {kind, namespace, access: ([.access[] | {resource, action}] | sort)}] | sort'
}

provision_harbor() {
  local api="${HARBOR_HOST_URL}/api/v2.0" i
  log "waiting for Harbor at ${HARBOR_HOST_URL}"
  for i in $(seq 1 120); do
    [[ "$(harbor_api "${api}/health" 2>/dev/null | jq -r .status)" == "healthy" ]] && break
    [[ ${i} -eq 120 ]] && die "Harbor not healthy at ${HARBOR_HOST_URL}"
    sleep 5
  done

  # Harbor defaults to "everyone", which lets any robot create projects regardless of its permissions.
  harbor_admin -X PUT "${api}/configurations" --data '{"project_creation_restriction":"adminonly"}' >/dev/null

  # The test project must stay private: resolving a project by name is gated on project:read,
  # a check every caller passes on a public project, which would hide a missing permission.
  local project
  project="$(harbor_admin "${api}/projects/${HARBOR_TEST_PROJECT}" 2>/dev/null || true)"
  if [[ -z "${project}" ]]; then
    log "creating private Harbor project ${HARBOR_TEST_PROJECT}"
    harbor_admin -X POST "${api}/projects" \
      --data "$(jq -n --arg p "${HARBOR_TEST_PROJECT}" '{project_name: $p, metadata: {public: "false"}}')" >/dev/null
  elif [[ "$(jq -r '.metadata.public' <<<"${project}")" != "false" ]]; then
    log "making Harbor project ${HARBOR_TEST_PROJECT} private"
    harbor_admin -X PUT "${api}/projects/$(jq -r .project_id <<<"${project}")" \
      --data '{"metadata":{"public":"false"}}' >/dev/null
  fi

  local spec="${ROOT_DIR}/testdata/harbor-provisioner-robot.json"
  local name secret="" robot
  name="$(jq -r .name "${spec}")"
  if [[ -s "${ENV_FILE}" ]]; then
    secret="$(
      # shellcheck source=/dev/null
      . "${ENV_FILE}"
      printf '%s' "${HARBOR_ROBOT_SECRET:-}"
    )"
  fi

  robot="$(find_system_robot "${name}" || true)"
  if [[ -n "${robot}" ]]; then
    local id detail
    id="$(jq -r .id <<<"${robot}")"
    # Keep the existing robot whenever its secret still authenticates: Vault's harbor/config
    # holds that secret, and a recreated robot would leave the mount pointing at a dead one.
    if [[ -n "${secret}" ]] &&
      harbor_as "robot\$${name}" "${secret}" -o /dev/null "${api}/robots?q=Level%3Dsystem&page_size=1" 2>/dev/null; then
      detail="$(harbor_admin "${api}/robots/${id}")"
      if [[ "$(normalize_permissions <<<"${detail}")" == "$(normalize_permissions <"${spec}")" ]]; then
        log "Harbor robot robot\$${name} is up to date"
      else
        log "updating permissions of Harbor robot robot\$${name}"
        # Send the stored name back verbatim; the spec's unprefixed name would rename the robot.
        # Omitting "secret" leaves it untouched.
        harbor_admin -X PUT "${api}/robots/${id}" --data "$(
          jq --slurpfile spec "${spec}" \
            '{name, description, duration, disable, level, permissions: $spec[0].permissions}' <<<"${detail}"
        )" >/dev/null
      fi
      HARBOR_ROBOT_NAME="robot\$${name}"
      HARBOR_ROBOT_SECRET="${secret}"
      return
    fi
    log "recreating Harbor robot robot\$${name}"
    harbor_admin -X DELETE "${api}/robots/${id}" >/dev/null
  else
    log "creating Harbor robot robot\$${name}"
  fi

  local created
  created="$(harbor_admin -X POST "${api}/robots" --data @"${spec}")"
  HARBOR_ROBOT_NAME="$(jq -r .name <<<"${created}")"
  HARBOR_ROBOT_SECRET="$(jq -r .secret <<<"${created}")"
}

write_env() {
  local tmp="${ENV_FILE}.tmp"
  (
    umask 077
    {
      echo "# Generated by scripts/kind-up.sh. Local test credentials only."
      printf 'export %s=%q\n' \
        VPH_KUBECONFIG "${KIND_KUBECONFIG}" \
        VAULT_ADDR "${VAULT_HOST_ADDR}" \
        VAULT_TOKEN "$(jq -r .root_token "${VAULT_INIT_FILE}")" \
        HARBOR_URL "${HARBOR_HOST_URL}" \
        HARBOR_INCLUSTER_URL "${HARBOR_INCLUSTER_URL}" \
        HARBOR_CA_CERT "${CA_CERT}" \
        HARBOR_ADMIN_USERNAME "${HARBOR_ADMIN_USERNAME}" \
        HARBOR_ADMIN_PASSWORD "${HARBOR_ADMIN_PASSWORD}" \
        HARBOR_ROBOT_NAME "${HARBOR_ROBOT_NAME}" \
        HARBOR_ROBOT_SECRET "${HARBOR_ROBOT_SECRET}" \
        HARBOR_TEST_PROJECT "${HARBOR_TEST_PROJECT}" \
        TEST_HARBOR_URL "${HARBOR_HOST_URL}" \
        TEST_HARBOR_USERNAME "${HARBOR_ROBOT_NAME}" \
        TEST_HARBOR_PASSWORD "${HARBOR_ROBOT_SECRET}" \
        TEST_HARBOR_CA_CERT "${CA_CERT}"
    } >"${tmp}"
    mv "${tmp}" "${ENV_FILE}"
  )
}

smoke_test() {
  local api="${HARBOR_HOST_URL}/api/v2.0"
  log "smoke test: Harbor over https from the host"
  harbor_api -o /dev/null "${api}/systeminfo"
  log "smoke test: provisioner robot can list robots"
  harbor_as "${HARBOR_ROBOT_NAME}" "${HARBOR_ROBOT_SECRET}" -o /dev/null "${api}/robots?q=Level%3Dsystem&page_size=1"
  # BusyBox wget has no CA flag; its OpenSSL-based ssl_client honours SSL_CERT_FILE.
  log "smoke test: Harbor over https from the Vault pod (verified against the test CA)"
  k -n "${VAULT_K8S_NAMESPACE}" exec -i vault-0 -c vault -- \
    sh -ec 'cat >/tmp/harbor-ca.pem; SSL_CERT_FILE=/tmp/harbor-ca.pem wget -q -O /dev/null "$1/api/v2.0/systeminfo"' _ "${HARBOR_INCLUSTER_URL}" <"${CA_CERT}"
  log "smoke test: plugin directory mounted in the Vault pod"
  k -n "${VAULT_K8S_NAMESPACE}" exec vault-0 -c vault -- test -d /vault/plugins
}

create_cluster
generate_certs
install_harbor
install_vault
init_vault
provision_harbor
write_env
smoke_test

log "environment ready; source ${ENV_FILE#"${ROOT_DIR}/"} for VAULT_ADDR, VAULT_TOKEN, HARBOR_* and TEST_HARBOR_*"
