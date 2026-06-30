# DPoP verification and X-Role mapping in openhim-core

Replaces the `fhir-gateway-mediator`: everything it did that is not already in
core moves into core, so a single OpenHIM channel can front `hie-fhir-server`.

## Scope

Two stacked deliveries:

1. **`feat/dpop`** — RFC 9449 DPoP proof verification for JWT-authenticated
   requests.
2. **`feat/dpop-x-role`** (on top of 1) — map Keycloak realm roles to a FHIR
   role and send it upstream as `X-Role`, per route, like `forwardAuthHeader`.
   Console gets the matching route checkbox.

Out of scope: channel auto-registration (admin creates channels), audit server
channel, DPoP for non-JWT auth types.

## Configuration (`config/default.json` → `authentication.jwt`)

| Key | Default | Meaning |
| --- | --- | --- |
| `dpopPublicBaseUrl` | `""` | Public URL clients use to reach OpenHIM, e.g. `https://hie.example.org`. Empty disables DPoP enforcement: a token carrying `cnf.jkt` is accepted as a plain bearer token (today's behaviour). Set: every token with `cnf.jkt` must be accompanied by a valid `DPoP` header whose `htu` equals `<dpopPublicBaseUrl><request path without query>`. |
| `roleMappings` | `""` | `realmRole=fhirRole` pairs, comma separated, e.g. `hip=ehr,hiu=patient`. Empty disables role mapping. |

Both env-overridable as `authentication_jwt_dpopPublicBaseUrl` /
`authentication_jwt_roleMappings` (nconf `_` separator).

## Part 1 — DPoP

### `src/constants.js`

`JWT_PATTERN` accepts scheme `Bearer` or `DPoP` (case-insensitive).

### `src/dpop.js` (new)

`verifyDpop({proof, accessToken, jkt, method, url})` → resolves on success,
throws `Error` with a specific message on failure. Uses `jsonwebtoken` and
`node:crypto` only; no new dependency.

Checks, in order (messages are what tests assert on):

1. `proof` present — `DPoP proof required`
2. Header `typ === 'dpop+jwt'`, `jwk` present, `alg` present and in
   `['RS256','RS384','RS512','PS256','PS384','PS512','ES256','ES384','ES512','EdDSA']`
   — `Malformed DPoP proof`
3. Signature verifies with `crypto.createPublicKey({key: jwk, format: 'jwk'})`
   and `algorithms: [header.alg]` — `DPoP signature invalid`
4. RFC 7638 thumbprint of `jwk` (canonical members per `kty`, SHA-256,
   base64url) equals `jkt` — `DPoP key does not match token`
5. `iat` present and `|now - iat| <= 300` s — `DPoP proof expired`
6. `htm === method` — `DPoP htm mismatch`
7. `htu === url` — `DPoP htu mismatch`
8. `ath === base64url(sha256(accessToken))` — `DPoP ath mismatch`
9. `jti` present and unseen — `DPoP proof replayed`. Replay cache is an
   in-process `Map<jti, iat>`, pruned of entries older than 300 s when it
   exceeds 10 000 entries. `ponytail:` per-process only; move to a shared store
   if core is scaled out (same ceiling the mediator had).

### `src/middleware/jwtAuthentication.js`

After `verify()` succeeds and before the client lookup: if
`decodedToken.cnf?.jkt` and `dpopPublicBaseUrl` is non-empty, call
`verifyDpop` with `proof = ctx.request.header.dpop`, `method =
ctx.request.method`, `url = dpopPublicBaseUrl + ctx.request.path`. Any throw
is logged at `error` and the request stays unauthenticated (existing catch
block → 401 from authorisation).

## Part 2 — X-Role

### `src/model/channels.js`

`RouteDef.forwardRoleHeader: {type: Boolean, default: false}` beside
`forwardAuthHeader`.

### `src/middleware/jwtAuthentication.js`

After successful authentication: parse `roleMappings` once per request
(`hip=ehr,hiu=patient` → `{hip:'ehr', hiu:'patient'}`), take
`decodedToken.realm_access?.roles ?? []`, set `ctx.jwtRole` to the mapped value
of the first realm role that has a mapping, else leave `ctx.jwtRole` undefined.

### `src/middleware/authorisation.js`

After a channel is authorised: if `channel.routes.some(r => r.forwardRoleHeader)`
and `!ctx.jwtRole` → `ctx.response.status = 403`, body
`Token has no realm role mapped by roleMappings`, do not set
`ctx.authorisedChannel`. Mirrors the mediator's 403.

### `src/middleware/router.js` `constructOptionsObject`

When `route.forwardRoleHeader` is true: delete any incoming `x-role` header
and set `options.headers['x-role'] = ctx.jwtRole`. When false: headers
untouched (backward compatible).

### Console (`openhim-console-master`, branch `feat/x-role`)

- `app/views/partials/channels-tab-routes.html`: Yes/No `uib-btn-radio` group
  "Forward mapped role as X-Role header" bound to `newRoute.forwardRoleHeader`,
  next to the existing "Forward existing Authorization header" group.
- `app/scripts/controllers/channel-tabs/routes.js`: default
  `forwardRoleHeader: false` in the new-route object; mediator-route import
  copies `endpoint.forwardRoleHeader` the same way it copies
  `forwardAuthHeader`.

## Client identity

Unchanged: JWT `sub` must equal an OpenHIM client's `clientID`. For Keycloak
service accounts `sub` is the service-account user UUID; each participant's
OpenHIM client uses that UUID as `clientID`.

## Testing (mocha, existing conventions)

- `test/unit/dpopTest.js`: happy path (ES256 key generated in-test), each
  failure message above, replay of same `jti`.
- `test/unit/jwtAuthenicationTest.js`: `DPoP` scheme accepted; DPoP enforced
  when `cnf.jkt` and base URL set; not enforced when base URL empty;
  `ctx.jwtRole` set from `realm_access.roles` via `roleMappings`; undefined
  when no mapping.
- `test/unit/routerTest.js`: `forwardRoleHeader` true sets `x-role` from
  `ctx.jwtRole` and drops the client-supplied one; false leaves headers alone.
- `test/unit/authorisationTest.js`: 403 when channel route has
  `forwardRoleHeader` and no `ctx.jwtRole`.
