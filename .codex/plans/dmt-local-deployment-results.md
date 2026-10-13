# DMT local deployment results

Test helpers were moved on 2026-10-11 to the separate sibling Git repository [dmt-certify-test-kit](../../../dmt-certify-test-kit/README.md). Generated lab state also lives in that repository's ignored `.local/dmt/` directory. Commands below run from the Inji Certify checkout and load the kit environment.

Deployed and checked on 2026-10-09, Asia/Colombo. Related guide: [deployment/testing plan](dmt-local-deployment-testing-plan.md).

## Running services

| Service | Address | Result |
| --- | --- | --- |
| Rebuilt Certify 0.14.0, `dmt-dev` profile | `http://localhost:8090/v1/certify` | Health `UP`; key setup completed |
| Certify PostgreSQL, dedicated container `dmt-certify-db` | `127.0.0.1:5433` | Current DDL/DML initialized |
| Go DMT mock, adapted lab copy | `http://127.0.0.1:8085` | Both synthetic ERL records available |
| Existing DMT PostgreSQL, `dmt-postgres` | `localhost:54320` | Existing records preserved; healthy |
| Public JWKS fixture | `http://localhost:8088/jwks.json` | Access JWT signature verification works |
| HTTPS gateway, context and DID fixture | `https://localhost:9443` | Normal TLS/hostname validation enabled |

The Go source was found at `/Users/bathiya/GovTech/dmt-mock-api` (`../../dmt-mock-api` from this checkout). Only `../dmt-certify-test-kit/.local/dmt/go-mock` was adapted to expose `GET /api/v1/erl/vehicles/{vehicleNo}` and query `vehicle_no` instead of `subject`. The original project was preserved. Its API runs behind a local HTTPS gateway because the Certify plugin requires HTTPS.

## Checks completed

- Maven on SDKMAN Java `21-local` (Java 21.0.12.1).
- 65 DMT plugin tests and 15 targeted issuance-service tests passed.
- Rebuilt application and DMT plugin packaged successfully; only the DMT JAR is loaded externally.
- `LoggerAuditService` comes from Certify itself; no external mock plugin is required.
- ERL configuration registered with HTTP 201; discovery advertises `ERLCredential`, `dmt_erl`, `ldp_vc`.
- Both vehicle responses contain the exact expected four ERL fields, plus the credential's holder-binding `id`.
- All three successful VCs passed independent Ed25519Signature2020 verification using PyLD and Python cryptography. Changing `vehicleNo` in each signed VC caused signature verification to fail.

| Acceptance case | HTTP | Go record calls | Outcome |
| --- | --- | --- | --- |
| `WP-ABC-1234` | 200 | 1 | `CHASSIS000001`, `2026-01-01`, `2026-12-31`; verified |
| `WP-CAB-5678` | 200 | 1 | `CHASSIS000002`, `2026-02-15`, `2027-02-14`; verified |
| Missing lookup | 400 | 0 | Rejected |
| Invalid vehicle number | 400 | 0 | Rejected |
| Wrong issuer | 401 | 0 | Rejected |
| Expired access token | 401 | 0 | Rejected; empty response body handled |
| Wrong audience | 401 | 0 | Rejected |
| Missing ERL scope | 400 | 0 | Rejected |
| Incorrect holder nonce | 400 | 0 | Rejected |
| Vehicle claim altered after JWT signing | 401 | 0 | Invalid signature rejected |
| Signed forged selection claim | 200 | 1 | Certify selected ERL from validated metadata; verified |

Evidence is in the ignored `../dmt-certify-test-kit/.local/dmt/output` directory: `plugin-tests.log`, `service-tests.log`, `build.log`, `registration-response.json`, `discovery.json`, `health.json`, `exercise-results.json`, `exercise.log`, issued synthetic VCs and per-VC verification logs. Generated private keys, bearer tokens and the signing keystore remain in the ignored lab directory.

## Operate the existing lab

Run from the repository root:

```sh
source ../dmt-certify-test-kit/.local/dmt/env.sh
"$LAB_DIR/venv/bin/python" "$TEST_KIT_ROOT/scripts/manage.py" status
curl --fail http://localhost:8090/v1/certify/actuator/health

# Fresh tokens/proofs, issuance and verification checks:
"$LAB_DIR/venv/bin/python" "$TEST_KIT_ROOT/scripts/exercise.py"

# After changing Certify's lab configuration/plugin JAR:
"$LAB_DIR/venv/bin/python" "$TEST_KIT_ROOT/scripts/manage.py" restart-certify
```

Stop the recorded host processes and databases without deleting their state:

```sh
"$LAB_DIR/venv/bin/python" "$TEST_KIT_ROOT/scripts/manage.py" stop
docker stop dmt-certify-db dmt-postgres
```

Restart an existing lab without repeating schema/key initialization:

```sh
source ../dmt-certify-test-kit/.local/dmt/env.sh
docker start dmt-certify-db dmt-postgres
"$LAB_DIR/venv/bin/python" "$TEST_KIT_ROOT/scripts/manage.py" start
```

## Scope of these results

This is a synthetic direct-issuance lab with a JWT fixture, not an OAuth login/consent or real wallet deployment. Vehicle entitlements are represented by the fixture's static map; integration with a real ownership authority is still required.

The gateway publishes Certify's actual generated public keys with explicit `assertionMethod` references. This fixture normalization means the successful checks do not establish interoperability of Certify's unmodified DID endpoint. The independent helper verifies cryptographic integrity and assertion authorization for this suite; broader credential validity, revocation and wallet trust policy remain separate checks.

All eight token/proof/lookup rejection cases above were exercised against the deployed service. Timeout, response-size and other transport/configuration cases were covered by the plugin tests; they were not all manually injected into the running mock. A Driving License strategy is still disabled and unimplemented.

## Test-kit migration check — 2026-10-11

The helpers and preserved lab state were moved to `../dmt-certify-test-kit`. All four host services were restarted using the new paths. Certify health returned `UP`, and all 11 acceptance cases passed again, including independent signature verification and credential-tamper rejection. Migration evidence is in `$LAB_DIR/output/migration-acceptance.log`. Generated private keys, tokens and keystores are excluded by the new repository's `.gitignore`.
