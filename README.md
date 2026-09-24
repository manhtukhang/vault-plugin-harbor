# Vault Plugin: Harbor robot account
[![GitHub license](https://img.shields.io/github/license/manhtukhang/vault-plugin-harbor.svg)](https://github.com/manhtukhang/vault-plugin-harbor/blob/main/LICENSE)
[![Release](https://img.shields.io/github/release/manhtukhang/vault-plugin-harbor.svg)](https://github.com/manhtukhang/vault-plugin-harbor/releases/latest)
[![CI](https://github.com/manhtukhang/vault-plugin-harbor/actions/workflows/ci.yml/badge.svg)](https://github.com/manhtukhang/vault-plugin-harbor/actions/workflows/ci.yml)
[![Integration Test](https://github.com/manhtukhang/vault-plugin-harbor/actions/workflows/integration.yml/badge.svg)](https://github.com/manhtukhang/vault-plugin-harbor/actions/workflows/integration.yml)
[![Security scanning](https://github.com/manhtukhang/vault-plugin-harbor/actions/workflows/snyk.yml/badge.svg)](https://github.com/manhtukhang/vault-plugin-harbor/actions/workflows/snyk.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/manhtukhang/vault-plugin-harbor)](https://goreportcard.com/report/github.com/manhtukhang/vault-plugin-harbor)
[![Maintainability](https://api.codeclimate.com/v1/badges/08cc4f11bf1bbb09b7a0/maintainability)](https://codeclimate.com/github/manhtukhang/vault-plugin-harbor/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/08cc4f11bf1bbb09b7a0/test_coverage)](https://codeclimate.com/github/manhtukhang/vault-plugin-harbor/test_coverage)

A [Vault](https://developer.hashicorp.com/vault) secrets engine plugin that issues short-lived
[Harbor](https://goharbor.io) robot accounts. Each `vault read <mount>/creds/<role>` creates a
new Harbor robot account bound to a Vault lease; revoking or expiring the lease deletes it.

Tested with Vault 2.0 and Harbor 2.15.

## Install

1. Download the binary for your platform from the
   [release page](https://github.com/manhtukhang/vault-plugin-harbor/releases), verify it against the
   published checksums, and copy it into the `plugin_directory` of every Vault server.

2. Register it with its SHA256 and version, then enable a mount:
   ```bash
   SHA256=$(sha256sum vault-plugin-harbor | cut -d ' ' -f1)
   vault plugin register -sha256="$SHA256" -version=v<version> \
       -command=vault-plugin-harbor secret harbor
   vault secrets enable -path=harbor -plugin-version=v<version> harbor
   ```

3. To upgrade, register the new binary the same way, then:
   ```bash
   vault secrets tune -plugin-version=v<new-version> harbor/
   vault plugin reload -plugin=harbor
   ```

See the Vault docs on [plugin registration](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-registration)
and [upgrading plugins](https://developer.hashicorp.com/vault/docs/upgrading/plugins).

Permissions are checked again every time a robot account is minted, not only when the role is
written, so a role stored by an earlier version fails closed. After upgrading, rewrite any role
using `namespace: "*"` (now behind `allow_all_projects`), `kind: "system"` or `effect: "deny"`:
until then its `creds/<role>` reads return an error naming the offending permission.

## Harbor principal

The plugin authenticates to Harbor with the configured username and password. Do not use the
Harbor admin account: create a dedicated **system robot account** with only what the plugin needs.

- system `/`: `robot` `create`, `read`, `list`, `delete`
- project `*`: `robot` `create`, `read`, `list`, `delete` (project-level robots are authorized
  against project permissions)
- project `*`: `project` `read`, so that the rollback of a failed request can resolve the project by
  name; without it Harbor answers 403 for a private project and the orphaned robot is left behind
- every project permission the Vault roles will grant. Harbor's creator-subset check rejects the
  creation of any robot asking for a resource the principal does not hold, so a principal narrower
  than the allowlist under [Roles](#roles) turns into per-role 403s at issuance.

```json
{
  "name": "vault-plugin-harbor",
  "description": "vault-plugin-harbor provisioner",
  "duration": -1,
  "level": "system",
  "disable": false,
  "permissions": [
    {
      "kind": "system",
      "namespace": "/",
      "access": [
        { "resource": "robot", "action": "create" },
        { "resource": "robot", "action": "read" },
        { "resource": "robot", "action": "list" },
        { "resource": "robot", "action": "delete" }
      ]
    },
    {
      "kind": "project",
      "namespace": "*",
      "access": [
        { "resource": "robot", "action": "create" },
        { "resource": "robot", "action": "read" },
        { "resource": "robot", "action": "list" },
        { "resource": "robot", "action": "delete" },
        { "resource": "accessory", "action": "list" },
        { "resource": "artifact", "action": "read" },
        { "resource": "artifact", "action": "list" },
        { "resource": "artifact", "action": "delete" },
        { "resource": "artifact-addition", "action": "read" },
        { "resource": "artifact-label", "action": "create" },
        { "resource": "artifact-label", "action": "delete" },
        { "resource": "label", "action": "read" },
        { "resource": "label", "action": "list" },
        { "resource": "log", "action": "list" },
        { "resource": "metadata", "action": "read" },
        { "resource": "metadata", "action": "list" },
        { "resource": "project", "action": "read" },
        { "resource": "quota", "action": "read" },
        { "resource": "repository", "action": "pull" },
        { "resource": "repository", "action": "push" },
        { "resource": "repository", "action": "list" },
        { "resource": "repository", "action": "read" },
        { "resource": "repository", "action": "delete" },
        { "resource": "sbom", "action": "create" },
        { "resource": "sbom", "action": "read" },
        { "resource": "sbom", "action": "stop" },
        { "resource": "scan", "action": "create" },
        { "resource": "scan", "action": "read" },
        { "resource": "scan", "action": "stop" },
        { "resource": "tag", "action": "list" },
        { "resource": "tag", "action": "create" },
        { "resource": "tag", "action": "delete" }
      ]
    }
  ]
}
```

When the principal is a robot, Harbor only lets it create robots whose permissions are a subset of
its own (same kind, namespace or `*`, resource, action and effect). The principal's own permission
set is therefore the ceiling for everything this engine can issue, whatever the roles ask for; see
[Security model](#security-model).

Harbor only authenticates robots whose name starts with its current `robot_name_prefix` (default
`robot$`), so the principal is configured under its prefixed name; see
[Robot account names](#robot-account-names).

## Configuration

```bash
vault write harbor/config \
    url="https://harbor.example.com" \
    username='robot$vault-plugin-harbor' \
    password="$HARBOR_ROBOT_SECRET" \
    ca_cert=@harbor-ca.pem
```

| Field | Description |
|:--|:--|
| `url` | Harbor URL. `https` only; no credentials, query or fragment. A trailing `/` or `/api/v2.0` is stripped. |
| `username` | Harbor principal (for a robot: `robot$<name>`). 1 to 255 characters of letters, digits and `._$+-`. |
| `password` | Password or robot secret. Never returned on read. |
| `ca_cert` | Optional PEM CA certificate(s) trusted in addition to the system roots. |
| `allow_all_projects` | Default `false`. Mount ceiling for the role field of the same name. |
| `robot_name_prefix` | Optional, default empty. Harbor's `robot_name_prefix` when it contains neither `$` nor `+`. At most 32 characters of letters, digits and `._$+-`; an empty value clears it. See [Robot account names](#robot-account-names). |
| `verify_connection` | Default `true`: checks the URL, TLS and credentials with an authenticated call needing only `robot:list` before storing. Not stored. |

- Changing `url` or `username` requires `password` in the same request, so that a config writer
  cannot point the stored password at a host they control. Changing only `ca_cert` does not, which
  is what makes a CA rotation possible without knowing the principal's secret: write the new and old
  certificates together while both are in play (`ca_cert` takes a PEM bundle), then write the new one
  alone once Harbor serves it.
- A `username` outside that character set is rejected with a 400 and the stored configuration is
  left as it was. Harbor's `q=` filter splits on `,`, keeps the last value of each key and unescapes
  twice, so a username carrying `,` or `=` could rewrite the filter this plugin sends when it looks
  for its own principal.
- `ca_cert` is parsed strictly: every PEM block of the bundle must be a `CERTIFICATE` that parses,
  and bytes that are not PEM, before, between or after the blocks, are rejected. A bundle with one
  corrupt block used to be accepted and to fail later as an opaque TLS handshake error.
- Reading `harbor/config` returns `url`, `username`, `ca_cert`, `allow_all_projects` and
  `robot_name_prefix`.
- With `verify_connection`, a write whose principal Harbor does not resolve to a robot account
  returns a warning, and a second warning names a principal that is a Harbor system administrator.
  Harbor's creator-subset check is the server-side ceiling on everything a role can grant and it
  binds robot principals only, so under a user principal it silently does not apply and the role
  allowlist is the only ceiling left.
- Connections use TLS 1.2+, ignore `HTTP(S)_PROXY`, never follow redirects and time out. Idempotent
  requests (`GET`, `DELETE`, `HEAD`) are retried, 3 attempts in all, with exponential backoff and
  jitter. `Retry-After` is honoured up to 5s and gives up at once beyond that, and no wait outlives
  the caller's deadline. `POST` and `PUT` are never retried: robot account creation and the password
  change stay single-shot, and the write-ahead log already covers an ambiguous create.

## Rotating the principal credentials

```bash
vault write -f harbor/config/rotate-root
```

Run it right after the first `vault write harbor/config`, so that no human knows the credentials
Vault uses. The response contains the new `username`, and the `robot_id` of the new robot account
when the principal is one.

- **Robot principal**: Harbor never lets a robot refresh its own secret, so Vault uses the current
  robot to create a new one with the same level, duration and permissions, verifies it, stores it,
  then deletes the previous robot. The name changes on every rotation: a `.r<unix time>` suffix is
  added or replaced (`robot$vault-plugin-harbor` becomes `robot$vault-plugin-harbor.r1700000000`).
  If the previous robot cannot be deleted, the response carries a warning with its ID.
- **User principal** (a local Harbor user): Vault sets a new random password. Harbor refuses this
  for LDAP and OIDC users; the error is returned and the configuration is unchanged.
- Leases issued before a rotation are still revoked. An interrupted rotation is undone, or
  completed if Harbor already accepted a new user password, by Vault's WAL rollback.

To rotate on a schedule (Kubernetes CronJob, CI job), give that job a token with only:
```hcl
path "harbor/config/rotate-root" {
  capabilities = ["update"]
}
```

## Roles

```bash
vault write harbor/roles/ci-pull ttl=15m max_ttl=1h permissions=@permissions.json
```

`permissions.json`:
```json
[
  {
    "kind": "project",
    "namespace": "library",
    "access": [
      { "resource": "repository", "action": "pull" }
    ]
  }
]
```

| Field | Description |
|:--|:--|
| `permissions` | JSON list of [Harbor robot permissions](https://github.com/goharbor/harbor/blob/v2.15.2/src/common/rbac/const.go). Required on creation. |
| `allow_all_projects` | Default `false`. Required to be `true` before a permission may use `namespace: "*"`, and only settable while the backend configuration allows it. |
| `ttl` | Default lease TTL. `0` uses the mount default. |
| `max_ttl` | Maximum lease TTL. `0` uses the mount maximum; must not exceed the mount maximum and must be `>= ttl`. |

Role names, and therefore `roles/<name>` and `creds/<name>` paths, must match
`[a-z0-9]+(?:[._-][a-z0-9]+)*` (lowercase). Updating a role only changes the fields sent.

Permission rules:
- `kind` must be `project`, with a lowercase project name as its `namespace`. `kind: "system"` is
  rejected: every system-scope permission Harbor offers reads the whole registry (`catalog` `read`
  lists every repository, `project` `list` enumerates every project, private ones included), so the
  system allowlist is empty.
- `namespace: "*"` is rejected with a 400 unless the role sets `allow_all_projects=true`. A wildcard
  namespace makes Harbor issue a **system-level** robot, which covers projects created after the
  role, can create projects on a default Harbor install, and can mount a layer from one project into
  another. It is opt-in for that reason, not for convenience.
- A role may only set `allow_all_projects=true` while `harbor/config` carries the same field, which
  is the mount-level ceiling: otherwise the role writer grants itself every project, present and
  future, in the same request as the permissions, which is the escalation the role field exists to
  gate. The ceiling is applied again when the role is read, so setting `allow_all_projects=false` on
  the configuration disarms the roles stored while it was `true`: their wildcard permissions are
  refused at issuance, and the role reads back with the field `false`.
- `access` is non-empty; `resource` and `action` are required and cannot be `*`.
- `effect` must be `allow` or empty, and is stored as empty, which is how Harbor stores it. `deny`
  is rejected: Harbor's creator-subset check compares effects verbatim against the principal's own,
  which are always allow, so a `deny` access could never be issued.
- Only data-plane `resource`/`action` pairs are accepted; everything else (project settings,
  members, robots, webhooks, preheat, replication, retention, immutability, scanners, system
  administration) is rejected:

  | Kind | Resource | Actions |
  |:--|:--|:--|
  | `project` | `repository` | `pull`, `push`, `list`, `read`, `delete` |
  | `project` | `artifact` | `read`, `list`, `delete` |
  | `project` | `tag` | `list`, `create`, `delete` |
  | `project` | `accessory` | `list` |
  | `project` | `artifact-addition` | `read` |
  | `project` | `artifact-label` | `create`, `delete` |
  | `project` | `scan`, `sbom` | `create`, `read`, `stop` |
  | `project` | `label`, `metadata` | `read`, `list` |
  | `project` | `project`, `quota` | `read` |
  | `project` | `log` | `list` |
- `repository` `pull` is added to every permission that grants `repository` `push` when the robot is
  minted; the stored role is left as written. Harbor derives the pull from the push for
  project-level robots only, so a `*`-scoped push-only role could not otherwise push.
- A role with exactly one `project` permission on a named project issues a project-level robot;
  anything else issues a system-level robot.

## Credentials

```bash
$ vault read harbor/creds/ci-pull
Key                         Value
---                         -----
lease_id                    harbor/creds/ci-pull/Wxidlpz1tVrb18XL7Zg4vPZM
lease_duration              15m
lease_renewable             true
robot_account_auth_token    cm9ib3QkbGlicmFyeSt2YXVsdC5jaS1wdWxsLnRva2VuLjE3MDAwMDAwMDAwMDAwMDAwMDA6c2VjcmV0
robot_account_id            42
robot_account_name          robot$library+vault.ci-pull.token.1700000000000000000
robot_account_secret        <secret>
```

| Key | Description |
|:--|:--|
| `robot_account_id` | Harbor robot ID. |
| `robot_account_name` | Full Harbor robot name, used as the registry username. |
| `robot_account_secret` | Robot secret, used as the registry password. |
| `robot_account_auth_token` | `base64(robot_account_name:robot_account_secret)`. |

- `creds/<role>` is read-only; each read creates a new robot account.
- A robot account Harbor returns under a name other than the one requested fails the read and is
  reclaimed by the WAL rollback: credentials for an account Vault did not name are credentials no
  revocation can reach.
- The Harbor robot expires one hour after the lease maximum (`max_ttl`, or the mount maximum),
  rounded up to whole days. Renewals never extend a lease past that maximum, even if the role is
  deleted.
- Revocation deletes the robot by ID from the Harbor that issued it, and is idempotent. It refuses to
  act if the configured `url` changed or the robot ID now belongs to a different name (see
  [Robot account names](#robot-account-names)).
- A robot created in Harbor by a request that then failed is deleted by Vault's WAL rollback, which
  identifies it by name and a per-request nonce in its description.

Revocation makes two Harbor calls, a read then a delete, both of them retried. A transient failure
that outlives those retries and Vault's own leaves an irrevocable lease behind and a robot account
that survives in Harbor until its own expiry, so a Harbor outage longer than the retry window is
paid for by hand.

When revocation keeps failing (Harbor unreachable, the configuration deleted, the robot ID now
belonging to another name), Vault retries and then marks the lease irrevocable.
`vault lease revoke -prefix harbor/creds/` does not clear those: it reports success and changes
nothing. Only `vault lease revoke -force -prefix harbor/creds/` clears them. `-force` still calls
this engine's revocation, but drops the lease whatever it returns: run it once Harbor is reachable
again and the robot account is deleted with the lease; forced while Harbor is still down, the lease
is gone and its robot account has to be deleted in Harbor by hand.

Leases issued by versions before this one do not record the robot ID and cannot be revoked by this
version: revoke them with `vault lease revoke -force -prefix harbor/creds/` and delete their
`vault.*` robots in Harbor.

## Robot account names

Vault names the robot accounts it creates `vault.<role>[.<token display name>].<unix nano>`, and
Harbor returns that name with its `robot_name_prefix` in front (default `robot$`), plus `<project>+`
for a project-level robot. The match is exact: the name Harbor reports must equal the name Vault
chose once that prefix is stripped, or equal `<prefix><name>`, or `<prefix><project>+<name>` for a
project robot. A robot account whose name merely ends with the one Vault chose is not a match and is
never deleted. The same rule applies when minting, revoking, rolling a WAL entry back, rotating the
principal, and deciding that a WAL entry describes the configured principal and must be left alone.

- The default prefix and the `<project>+` separator need no configuration: both end in `$` or `+`,
  which is enough to tell the prefix from the name. A custom prefix carrying neither (`robot_`,
  `bot-`) has to be declared as `robot_name_prefix` on `harbor/config`, otherwise a robot account
  wearing it cannot be told apart from one actually named that way.
- A `rotate-root` re-derives the prefix from what Harbor prepended to the name it asked for, so it
  stays correct afterwards. Changing `url` or `username` drops it, since it described the principal
  of the previous configuration; the same request may set `robot_name_prefix` to the prefix of the
  new one.
- Changing `robot_name_prefix` in Harbor invalidates every credential already issued, immediately:
  Harbor only authenticates robots whose name starts with the current prefix. Write the principal's
  new name with `vault write harbor/config username=<prefix><name> password=...`, adding
  `robot_name_prefix` when the new prefix carries no separator.

## Logging

At info: a robot account issued (role, robot account ID and name, level, project, Harbor URL and the
lease maximum), a revocation done, a revocation that found the robot account already gone, and a
completed `rotate-root` on either branch (previous and new robot account ID with the new username
for a robot principal, the username for a local user). At warn: a lease whose internal data is
incomplete, naming the field that is missing, since the robot account then stays live in Harbor
until an operator deletes it. No secret, password, auth token or nonce is ever logged.

With an audit device enabled, `robot_account_id` appears in cleartext in the audit log next to the
lease ID, because Vault HMACs strings but not integers. It is the only join key between a Vault
lease and a Harbor robot account.

## Rate limiting

Every read creates a Harbor robot account that lives until its lease ends. There is no per-role cap,
so limit issuance with a Vault [rate limit quota](https://developer.hashicorp.com/vault/docs/concepts/resource-quotas):

```bash
vault write sys/quotas/rate-limit/harbor-creds path='harbor/creds/*' rate=10 interval=1m
```

## Example policies

Consumer. Returning the credential when the job ends is what makes it short-lived, so the policy
has to allow revocation:
```hcl
path "harbor/creds/ci-pull" {
  capabilities = ["read"]
}

path "sys/leases/revoke" {
  capabilities = ["update"]
}

path "sys/leases/revoke/harbor/creds/ci-pull/*" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}
```

`vault lease revoke` sends the lease ID in the URL while the HTTP API and the Go client send it in
the body, so both revoke rules are needed. Renewal is only ever sent as a body parameter to
`sys/leases/renew`, which cannot be scoped to one lease; drop that rule if the consumer never renews.

Name one exact role path. `path "harbor/creds/*"` grants every role on the mount, push and delete
roles included, and `path "harbor/*"` adds `config` and `roles` on top of that. Where a wildcard
cannot be avoided, use `harbor/creds/+`: `+` matches a single path segment, unlike `*`, which
matches the rest of the path.

Role manager (can grant anything the Harbor principal holds, within the allowlist above):
```hcl
path "harbor/roles" {
  capabilities = ["list"]
}

path "harbor/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

Admin:
```hcl
path "harbor/config" {
  capabilities = ["create", "read", "update"]
}

path "harbor/config/rotate-root" {
  capabilities = ["update"]
}

path "harbor/roles" {
  capabilities = ["list"]
}

path "harbor/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/leases/lookup/harbor/creds*" {
  capabilities = ["list"]
}

path "sys/leases/revoke" {
  capabilities = ["update"]
}

path "sys/leases/revoke/harbor/creds/*" {
  capabilities = ["update"]
}

path "sys/leases/revoke-prefix/harbor/creds*" {
  capabilities = ["update", "sudo"]
}

path "sys/leases/revoke-force/harbor/creds*" {
  capabilities = ["update", "sudo"]
}
```

`harbor/config` is an exact rule and does not cover `harbor/config/rotate-root`, which needs the
rule of its own above. `delete` is left out on purpose: revocation reads the configuration to reach
Harbor, so deleting it leaves every outstanding lease permanently unrevocable and its robots alive
in Harbor. Overwrite the configuration instead.

## Security model

Read this before pointing the engine at a production Harbor.

- **Write access to `roles/*` is a privilege boundary.** Within the allowlist above, a role writer
  can hand out, through `creds/<role>`, anything the Harbor principal is able to grant, on any
  project the principal can reach. Restrict it as tightly as the principal's own secret, `config`
  and `config/rotate-root` included.
- **The Harbor principal's own permission set is the real ceiling.** Harbor bounds a robot account
  to the permissions of the robot account that creates it, so scope the principal to concrete
  projects where they are known, one `project` entry each, rather than namespace `*`. A user
  principal is not bounded at all, and a Harbor system administrator puts every project and every
  Harbor setting in reach of the mount; both are reported as warnings when the configuration is
  written.
- **One mount per trust boundary.** A role name is not a tenancy boundary: `permissions` may name
  any Harbor project regardless of what the role is called, so letting a team manage
  `harbor/roles/team-a-*` does not confine it to project `team-a`, and it can write a role granting
  `push` on any project the principal can reach. Isolating teams takes one mount per team, each with
  its own Harbor principal scoped to that team's projects.
- **Seed the principal, then rotate it at once** with `vault write -f harbor/config/rotate-root`, so
  the value a human typed stops working and nobody knows the one Vault uses.
- **Set Harbor's `project_creation_restriction` to `adminonly`.** The default, `everyone`, lets any
  system-level robot account, the ones this engine issues included, create projects whatever its
  permissions say.

## Development

```bash
make test      # unit tests with an in-process fake Harbor
make kind-up   # local kind cluster with Harbor and Vault
make testacc   # acceptance test against that Harbor
```

The acceptance test runs with `VAULT_ACC=1` and reads `TEST_HARBOR_URL`, `TEST_HARBOR_USERNAME`,
`TEST_HARBOR_PASSWORD` and `TEST_HARBOR_CA_CERT` (path to a PEM file). It uses the `library`
project and deletes every robot it creates.
