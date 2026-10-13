# Per-credential expiration for the DMT provider plugin

## Objective

Support ERL and driving-licence credentials through the same DMT provider plugin while allowing each credential strategy to determine its expiration from its own authoritative source record. The signed VC and its ledger entry must use the same expiration instant.

This document is an implementation plan. No Java implementation or runtime configuration changes are part of this planning task.

## Current behavior

- `MasterDataProviderPlugin` resolves a credential strategy through `VcDataFetcherRegistry` using Certify's selected scope.
- `ErlDataFetcher` retrieves and validates the ERL record. `ErlResponseDto` exposes `issueDate` and `expireDate` as business attributes.
- `VcData` currently contains only `Map<String, String> attributes`.
- `CertifyIssuanceServiceImpl` calculates `validUntil` from issuance time plus `mosip.certify.data-provider-plugin.vc-expiry-duration`, with a default of `P730D`.
- That duration is a default, not an enforced maximum lifetime.
- The ERL template maps `${validUntil}` to the VC's `expirationDate`. Its `credentialSubject.expireDate` is a separate source-record field.
- `CredentialLedgerServiceImpl` saves issuance metadata but does not assign the existing `Ledger.expirationDate` property.
- The driving-licence route is currently disabled. Its fetcher and source-response contract must be implemented before licence issuance can be tested.

## Intended behavior

| Credential | Strategy | Authoritative expiry |
| --- | --- | --- |
| ERL | `ErlDataFetcher` | Expiration of the vehicle's ERL record |
| Driving licence | `DrivingLicenseDataFetcher` | Expiration of the driving-licence record |
| Other provider credentials | Their registered strategy | Provider expiry when supplied; otherwise Certify's configured default duration |

The common issuance service must not contain ERL or driving-licence branches. It accepts generic validity metadata, resolves the final expiration once, and uses that result for both rendering and ledger persistence.

## Expiration rules

1. Each fetcher derives expiry from the validated upstream record, not from the wallet request or bearer-token claims.
2. Represent credential expiration as an `Instant` internally and as an ISO-8601 UTC timestamp at the JSON boundary.
3. For a source containing only a calendar date, agree on the business time zone and whether the date is inclusive. If valid throughout that date, use the start of the following day in that zone as the exclusive expiration instant. Do not assume a date means midnight UTC.
4. Reject an already-expired source record. Validate the source's date ordering and the resolved expiration against issuance time.
5. Distinguish absent validity metadata from invalid metadata. Absence may use the configured default; malformed or expired metadata must fail rather than silently falling back.
6. Do not introduce a maximum-lifetime cap as part of this change. A separate issuer policy would be required if a cap is desired later.

## Implementation steps

### 1. Extend the plugin's internal result

Update `inji-certify/dmt-dataprovider-plugin/src/main/java/lk/gov/dmt/certify/plugin/model/VcData.java` to carry validity metadata separately from business attributes.

Conceptual contract:

```java
record VcData(Map<String, String> attributes, Instant validUntil) {}
```

Document whether a missing expiration is permitted. Preserve immutable attributes and redacted logging. Do not place internal validity metadata inside the credential subject automatically.

### 2. Derive validity in each strategy

- Update `ErlDataFetcher` and/or `ErlResponseDto` to derive `validUntil` from the ERL's `expireDate` using the agreed date semantics.
- Implement the driving-licence fetcher and response DTO so they derive validity from the licence's own expiration field.
- Keep credential-specific rules in their credential packages. Introduce a shared date-conversion helper only where the semantics are actually shared.
- Use an injected `Clock` where current time is required so expiration-boundary tests are deterministic.

### 3. Define the common provider-to-Certify metadata contract

The public `DataProviderPlugin.fetchData()` contract returns a JSON object, so extending the plugin's internal `VcData` alone is insufficient.

- Define an optional, reserved validity metadata object in the common Certify provider API. A proposed shape is `_certifyValidity: { "validUntil": "<ISO-8601 instant>" }`; finalize its name after checking existing reserved fields.
- Update `MasterDataProviderPlugin` to serialize the internal validity separately from the business attributes.
- Document reserved-field ownership and remove this metadata before treating the remaining provider data as business attributes.
- Existing providers that omit the metadata must continue to work with the configured default expiration.

### 4. Resolve expiration once in Certify

Update `inji-certify/certify-service/src/main/java/io/mosip/certify/services/CertifyIssuanceServiceImpl.java` around the existing expiry calculation.

- Parse and validate the optional provider validity metadata after fetching data.
- Use the supplied expiration when present. Otherwise retain the existing configured-duration behavior.
- Keep one resolved expiration instant and populate `VCDM2Constants.VALID_UNTIL` from it.
- Continue to set issuance time separately; the ERL's original issue date remains a business attribute.
- Apply the same generic contract across supported formats without adding strategy-specific branches.

### 5. Persist the same expiration in the ledger

- Extend `CredentialLedgerService.storeLedgerEntry()` and its implementation to accept expiration alongside issuance time. Update affected callers and test doubles.
- Set `ledger.setExpirationDate(...)` from the same resolved expiration used for the VC.
- The existing entity and SQL schema already contain `expiration_date`; no new column is needed.
- Because the current column and entity use a timestamp without zone and `LocalDateTime`, convert the instant explicitly to UTC before storing it and document that convention.
- Preserve existing ledger enable/disable behavior. Existing rows with a null expiration will remain unchanged unless a separate backfill is requested.

### 6. Keep templates aligned

The current ERL template in `dmt-certify-test-kit/scripts/prepare_erl_config.py` already maps `${validUntil}` to `expirationDate`, so it can continue using that value.

The licence template should consume the same resolved value in the field appropriate to its credential format. Avoid calculating expiration independently inside templates, which could cause the signed VC and ledger to disagree.

## Verification

- ERL and licence fixtures with different source expirations produce their respective VC expirations when issued at the same time.
- Date-only conversion honors the chosen time zone and inclusive-date boundary.
- Missing provider validity uses the configured default duration.
- Invalid and already-expired provider validity fails issuance.
- The signed VC's expiration and the ledger expiration represent the same instant, and the ledger credential ID matches the VC ID.
- The business source expiry remains in the credential subject when required by the template.
- Existing rejection scenarios and independent signature/tamper checks continue to pass.
- Existing providers without the new metadata retain their current behavior.

Use focused plugin and Certify service tests for date resolution and persistence. Extend the test-kit acceptance runner with expiration assertions and add licence acceptance coverage after its strategy and mock endpoint exist.

## Build and test-lab rollout

1. Build the affected Certify modules and DMT plugin, then run their focused tests.
2. Refresh the test kit's runtime configuration and copied plugin JAR; restart Certify with the updated service JAR.
3. Update registered credential configurations only if their templates change. Editing the template-generation script alone does not update the database configuration.
4. For a clean acceptance run, use `dmt-certify-test-kit/scripts/reset-test-environment.sh`, which clears prior lab data and re-registers ERL configuration.
5. Run acceptance checks, inspect the returned signed VCs, and compare their IDs and expiration instants with `certify.ledger`.

## Out of scope

- Permanent storage or backup of complete VCs.
- Wallet recovery, revocation policy, or historical ledger backfill.
- Introducing a new issuer maximum-lifetime policy.
- Changing production deployment configuration as part of the test-kit rollout.
