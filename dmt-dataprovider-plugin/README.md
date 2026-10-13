# DMT Data Provider Plugin

ERL lookup uses `GET /api/v1/erl/vehicles/{vehicleNo}`. The registry selects the strategy from Certify's validated selected scope; the ERL strategy selects the record using the vehicle number in the authenticated token.

## Token contract

The authorization server must authenticate the user and verify entitlement to the selected vehicle before issuing the signed token. Certify's normal access-token validation must validate that token. The DMT client also requires an exact match against its configured `trusted-issuer`.

Example decoded claims (not a token to submit directly):

```json
{
  "iss": "https://identity.example.gov.lk",
  "sub": "user-123",
  "scope": "dmt_erl",
  "credential_lookup": {
    "vehicleNo": "WP-ABC-1234"
  }
}
```

Certify adds `_certifySelectedScope` after validating credential selection and proof. The wallet does not supply that reserved value. Lookup attributes are copied from the token's `credential_lookup` object, never from the credential request body, a top-level vehicle claim or `sub`. Missing `vehicleNo` fails before the API call.

The plugin validates input and issuer but cannot establish vehicle ownership itself: the entitlement check is a required authorization-server integration. Possessing the service API key or the ERL scope alone does not prove ownership. DMT must authorize the service's access to this endpoint.

For this assumed contract, `vehicleNo` is canonical ASCII letters/digits separated by single hyphens, with a maximum length of 32. No trimming, case conversion or punctuation normalization is performed. The returned vehicle number must match exactly. Align this rule with the actual DMT plate format before deployment.

## Configuration and deployment

Use [examples/application.yml](examples/application.yml) as an external configuration fragment. Supply `DMT_API_BASE_URL`, `DMT_API_KEY` and `DMT_IDENTITY_ISSUER`; keep the existing audit plugin's scan package in `CERTIFY_INTEGRATION_SCAN_PACKAGES`. A base URL path, if supplied, prefixes the endpoint path.

Build with Java 21 from the repository root:

```sh
mvn -pl dmt-dataprovider-plugin -am package -Dgpg.skip=true
```

Place the resulting plain plugin JAR in Certify's configured loader path and restart. The example is opt-in; it does not replace the current local configuration. Ensure its values take precedence over profile-specific or config-server settings. Register the ERL credential configuration separately with scope `dmt_erl`, template fields `vehicleNo`, `chassisNo`, `issueDate`, `expireDate`, and the issuer's actual context and signing metadata.

For a container image containing this fork's Certify service and DMT plugin together, see [the DMT image build and deployment instructions](../certify-service-with-dmt/README.md).

## Future strategies

`MasterDataProviderPlugin` delegates authenticated-claim validation to `ProviderRequestFactory`, resolves the selected scope through `VcDataFetcherRegistry`, and passes its resolved route to the strategy. Both are in `application`; immutable requests and results are in `model`.

Each strategy implements `spi.VcDataFetcher`: `strategyId()`, optional `validateRoute(route)` for startup checks, and `fetch(request, route)`. Inject the `spi.DmtDataClient` interface to call `get(route, request, pathVariables)`. The `transport.DmtApiClient` implementation enforces exact path variables, HTTPS/origin checks, authentication, timeouts, redirects and response size. ERL-specific code is in `credential.erl`; shared configuration and validators are in `config` and `validation`.

For example, a future Driving License strategy could require `{licenseNo}`, validate the signed `credential_lookup.licenseNo`, parse the upstream response into a credential-specific DTO, and return only allowed `VcData` fields. Register that strategy as a Spring bean, then enable its scope, strategy ID, client and endpoint in configuration. The registry and master plugin need no credential-specific branches. Internal strategy signatures changed in this refactor, so separately compiled strategies must be rebuilt.

## Tests

```sh
mvn -pl dmt-dataprovider-plugin -am test
```

Tests use a local HTTPS server and a test-only TLS keystore; no DMT service is contacted. Coverage includes signed-claim extraction, immutable lookup data, missing/invalid vehicle numbers, named endpoint expansion, response vehicle mismatch, disabled routes, malformed responses, redirects, response-size limits and exchange deadlines.
