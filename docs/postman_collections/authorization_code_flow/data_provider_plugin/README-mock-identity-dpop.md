# Mock-identity collections: Bearer and DPoP

Two collections share one environment:

| Postman name | File | What it does |
|---|---|---|
| `Inji Certify With Mock Identity` | `inji-certify-with-mock-identity.postman_collection.json` | Bearer credential issuance |
| `Inji Certify With Mock Identity DPoP` | `inji-certify-with-mock-identity-dpop.postman_collection.json` | DPoP-constrained issuance (RFC 9449) |
| `ENV Mock Identity` | `inji-certify-with-mock-identity.postman_environment.json` | shared by both |

Both collections must use the **same** environment. The Bearer collection's `6. Get Tokens V2` publishes `unbound_access_token` into it, and the DPoP scenarios use that as the "token with no `cnf.jkt`" fixture.

## Run order

Clients first, if they are not registered yet: `Inji Certify With Mock Identity DPoP` → **OIDC Client Mgmt (DPoP)** for `dpop-wallet-demo`, and `Inji Certify With Mock Identity` → **OIDC Client Mgmt** for `wallet-demo`, once per deployment. Skip it against the local docker-compose stack — `setup-esignet.mjs` registers both clients there. See *Client registration*.

1. `Inji Certify With Mock Identity` → **VCI** folder, top to bottom. `2. Authorize / OAuthdetails request V2` must run before `3. Send OTP` — it sets `transaction_id`, `oauth_details_key` and `oauth_details_hash`.
2. `Inji Certify With Mock Identity DPoP` → **VCI (DPoP)** folder (steps 1–8, in order).
3. `Inji Certify With Mock Identity DPoP` → **DPoP scenarios**. These depend on both `access_token` (bound, from step 2) and `unbound_access_token` (from step 1).

## Switching deployments

The environment ships pointing at a **local** deployment. To run the VCI flow against one of MOSIP's hosted deployments, change these variables and no others — in particular leave `certifyUrl` and `audUrl` alone, for the reason below:

| Variable | Local (as shipped) | MOSIP released | MOSIP collab |
|---|---|---|---|
| `authServerUrl` | `http://localhost:8188/v1/esignet` | `https://esignet-mock.released.mosip.net/v1/esignet` | `https://esignet-mock.collab.mosip.net/v1/esignet` |
| `aud` | `http://localhost:8188/v1/esignet/oauth/v2/token` | `https://esignet-mock.released.mosip.net/v1/esignet/oauth/v2/token` | `https://esignet-mock.collab.mosip.net/v1/esignet/oauth/v2/token` |
| `mockIdentitySystemUrl` | `http://localhost:8182/v1/mock-identity-system` | `https://api.released.mosip.net/v1/mock-identity-system` | `https://api.collab.mosip.net/v1/mock-identity-system` |
| `internalUrl` | *(unused)* | `https://api-internal.released.mosip.net` | `https://api-internal.collab.mosip.net` |
| `relayingPartyId` | `mock-relying-party-id` | `mock-relying-party-id` | `mpartner-default-esignet` |

`internalUrl` and `partnerSecret` are needed only to register clients, not to run the flow — see *Registering clients on a hosted deployment* below. The published environment ships `internalUrl` empty, and `partnerSecret` empty because it is deployment-specific and must not be committed.

### `certifyUrl` and `audUrl` do not change

Both describe **certify**, which stays on `http://localhost:8091` no matter which eSignet you point at. Switching `authServerUrl` to a hosted host and dragging `audUrl` along with it is the single most common way to break this suite.

`8. Get Farmer Credential` signs the OpenID4VCI proof with `"aud": audUrl`, and `JwtProofValidator` compares it as an exact string against certify's `mosip.certify.identifier`. It must equal the `credential_issuer` value certify advertises:

```bash
curl -s $certifyUrl/.well-known/openid-credential-issuer \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['credential_issuer'])"
```

A wrong `audUrl` fails with `400 invalid_proof` — the same error as a wrong `iss`, a missing `iat`, or an unsupported `alg`, and indistinguishable from them without reading certify's log. A stale `c_nonce` is the one nearby failure that reports differently: `400 invalid_nonce`.

`http://certify-nginx:80` is certify's identifier only when certify itself runs **inside** the docker-compose network. Running certify as a host JVM it is `http://localhost:8091`, and the compose-internal hostname resolves nowhere.

### Which deployments can run the DPoP collection

DPoP arrived in eSignet **1.8**, so this depends on the host's build:

| Deployment | eSignet | DPoP |
|---|---|---|
| `esignet-mock.released.mosip.net` | 1.8.0 | yes — `dpop_signing_alg_values_supported: ["RS256","PS256"]` |
| `esignet-mock.collab.mosip.net` | pre-1.8 | no — issues tokens with no `cnf.jkt` |
| local eSignet 1.8+ | 1.8+ | yes |

Against collab the **Bearer** collection works and every DPoP scenario fails by construction: without `cnf.jkt` certify can only ever answer "access token is not DPoP-bound".

Note the advertised algorithms are RSA only. A wallet key on an EC curve is rejected at the token endpoint, and the error does not name the algorithm.

### eSignet's issuer differs per deployment

Certify's `mosip.certify.authn.issuer-uri` must equal the token's `iss` claim exactly (`JwtIssuerValidator`), and hosted eSignets disagree about what that is:

| Deployment | `iss` in the access token |
|---|---|
| released | `https://esignet-mock.released.mosip.net` |
| collab | `https://esignet-mock.collab.mosip.net/v1/esignet` |

Collab's discovery document advertises the bare host while its tokens carry the `/v1/esignet` suffix; released's discovery and tokens agree. Neither rule generalises — decode a real token per environment and copy its `iss`. A mismatch gives `401 invalid_token` / "The access token is invalid."

## Client registration

Two OIDC clients are expected, differing only in `dpop_bound_access_tokens`:

| Env variable | Client id | `dpop_bound_access_tokens` | Used by |
|---|---|---|---|
| `clientId` | `wallet-demo` | `false` | Bearer flow; also the unbound-token fixture |
| `dpopClientId` | `dpop-wallet-demo` | `true` | DPoP flow |

Both authenticate with `private_key_jwt`, each with its own key — `dpop_privateKey_jwk` and `privateKey_jwk`.

Each is registered from its own collection: `dpop-wallet-demo` by **`OIDC Client Mgmt (DPoP)`** in the DPoP collection, `wallet-demo` by **`OIDC Client Mgmt`** in the Bearer one. Both **generate their own keypair** and write the private half back into the environment before sending, so nothing has to be present beforehand and nothing pasted in afterwards: register, then run the flow. `Create DPoP client` additionally restores the previous private half if registration fails, rather than leaving the environment holding a key eSignet never saw. Against the local docker-compose stack `local-dev/dpop-test/setup-esignet.mjs` has already registered both and neither folder is needed.

`Create DPoP client` posts to `client-mgmt/client`, **not** `client-mgmt/oidc-client`. The v1 `oidc-client` endpoint drops `additionalConfig`, so a client registered through it is never DPoP-bound — and nothing says so: registration succeeds, the token comes back without `cnf.jkt`, and every scenario then fails with "access token is not DPoP-bound".

They cannot share one key: eSignet enforces a unique public key per client and rejects the second registration with `duplicate_public_key`.

Note `wallet_private_key` is a **different** key again — it signs the DPoP proofs and is what `cnf.jkt` fingerprints. `dpop_privateKey_jwk` proves *which client* is calling; `wallet_private_key` proves *which sender* holds the token.

### Registering clients on a hosted deployment

Against a local eSignet container `client-mgmt` is unauthenticated: run requests 2–3 of the folder and skip request 1, which has nothing to talk to (`internalUrl` ships empty). On collab and released it is a Spring OAuth2 resource server, so registration needs a partner token first.

1. **`1. Authenticate (partner)`** → `{{internalUrl}}/v1/authmanager/authenticate/clientidsecretkey` with `appId: partner`, `clientId: mosip-pms-client`, and that deployment's secret. The token comes back in the **`Set-Cookie` header**, not the body — the body only carries `{status, message}`. The test script extracts it into `authToken`.
2. **`2. Get CSRF token`** → the body value, not the cookie (see *CSRF* below).
3. **`3. Create DPoP client`**. The Bearer collection's `Create OIDC client` needs the same two steps ahead of it; it has no `Authenticate (partner)` request of its own, but `authToken` is in the shared environment, so running request 1 here covers both.

Three things reliably go wrong here:

- **The token goes in a header, not a cookie.** `Authorization: Bearer <token>` works; `Cookie: Authorization=<token>` is ignored and answers `Full authentication is required to access this resource` at HTTP 200. A malformed token is different again: HTTP 401 with an **empty body** and the real reason in the `WWW-Authenticate` response header. Read that header — it distinguishes `Malformed token` from `expired` from `insufficient_scope`, none of which appear in the body.
- **The token must carry `add_oidc_client`.** Decode it and check `scope`. A token from the wrong appId authenticates fine and still cannot register.
- **The partner secret is deployment-specific.** It is deliberately *not* committed: set `partnerSecret` in your own environment. A secret from one deployment gives `401 Unauthorized` on another, surfaced as `{"errorCode":"500","message":"401 Unauthorized: [no body]"}`.

### The registered public key cannot be changed

`PUT /client-mgmt/oidc-client/{clientId}` rejects a `publicKey` field outright — `ClientDetailUpdateRequestV3` has no such property — and there is no `GET` to read a registered key back.

So the moment a clientId exists it is welded to the key it was created with. If that private half is lost, the client is unusable and re-registering answers `duplicate_client_id`. **Use a new clientId** — there is no recovery path.

Both `Create …` requests generate a **fresh keypair on every run**, so the only copy of a registered client's private half is the one written into your environment. Two consequences: do not re-run them casually against a deployment where the client already exists, and do not click **Reset All** afterwards — that restores the committed demo keys over the working one. To keep a registered client, export the environment, or copy `dpop_privateKey_jwk` somewhere.

`additionalConfig` *is* updatable, so `dpop_bound_access_tokens` can be flipped in place on an existing client without touching its key.

## The committed keys are demo-only

`privateKey_jwk`, `dpop_privateKey_jwk`, `wallet_private_key` and `other_private_key` are complete RSA private keys, including `d`, `p` and `q`. They are committed to a public repository, so they are public from the moment they merge and must be treated as compromised.

They exist so the collections run against a local mock-identity stack with no setup. **Never register them with an authorization server that issues tokens for anything real**, and never reuse them outside this demo. To rotate, generate a fresh keypair, re-register the client with the new public half, and replace the private half here.

## Notes

- **CSRF.** eSignet 1.8 (Spring Security 6, BREACH protection) puts the raw token in the `XSRF-TOKEN` cookie and a masked token in the response body. `X-XSRF-TOKEN` must carry the **body** value; sending the cookie value gives `403 Forbidden` with an empty `path`.
- **DPoP nonce.** eSignet always rejects the first DPoP token request with `400 use_dpop_nonce` and a `DPoP-Nonce` header. Step 6 retries automatically with the nonce folded into the proof; this is expected, not a failure.
- **PKCE.** `codeVerifier`, `codeChallenge`, `codeChallengeMethod`, `code` and `client_assertion` are collection-scoped in both collections and deliberately absent from the environment. An environment variable of the same name would shadow the collection value — an empty one breaks PKCE with `unsupported_pkce_challenge_method`.
- **Initial vs Current value.** Postman stores two values per variable and `pm.environment.get()` reads only **Current**. Importing or syncing an environment routinely leaves Current blank while Initial still displays the data, so a variable looks populated and reads as `""`. Four variables are supplied by the environment file alone and no script ever rewrites them — `pmlib_code`, `dpop_lib`, `wallet_private_key`, `other_private_key` — so for those a blank Current value never self-heals. The symptom is `JSONError: No data, empty input at 1:1` in a pre-request script, which does not name the variable. The client keys are not in that class: `dpop_privateKey_jwk` is written by `Create DPoP client` and `privateKey_jwk` by the Bearer collection's `Create OIDC client`, so running those repairs a blank value. **Reset All** in the environment editor copies Initial into Current for every row. Note this also restores `privateKey_jwk` and `dpop_privateKey_jwk` to the committed demo keys, which will not match a client you registered yourself.
- **Exports carry Initial values.** Exporting an environment writes the Initial column, so a shared export cannot capture a working hosted configuration and must never be used to check what someone was actually running.
