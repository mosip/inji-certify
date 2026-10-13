# DMT Provider Modularization Plan

## Goal and compatibility

Organize the existing `dmt-dataprovider-plugin` Maven module as one deployable JAR. Preserve the Certify `DataProviderPlugin` SPI, `MasterDataProviderPlugin` selector, configuration keys, ERL behavior, failure categories, transport protections, and credential output. Internal Java packages and the fetcher contract may change; separately compiled strategies must rebuild.

## Package design

| Package under `lk.gov.dmt.certify.plugin` | Responsibility |
| --- | --- |
| base | `MasterDataProviderPlugin` SPI adapter and `DmtPluginConfiguration` composition root |
| `application` | Authenticated request creation and immutable strategy registry |
| `spi` | `VcDataFetcher` and `DmtDataClient` interfaces |
| `model` | Immutable request and business-data records |
| `config` | Spring-bound provider properties |
| `validation` | Configuration, endpoint-template, and shared text validation |
| `transport` | HTTPS client, safe request URI construction, bounded response subscriber |
| `credential.erl` | ERL lookup strategy and response DTO |
| `error` | Safe exchange failures |

Keep models free of Spring and HTTP dependencies. ERL depends on the client interface, while transport implements it. Add no extra Maven modules or speculative credential strategies.

## Implementation

1. Move existing types into their packages and update imports, preserving the root Spring configuration and plugin class names.
2. Extract selected-scope and claim validation into `ProviderRequestFactory`; retain claim limits, immutable lookup copies, validation order, and safe errors.
3. Change `VcDataFetcher.fetch` to accept the registry-resolved route. Add `validateRoute` for startup strategy checks. Remove ERL's independent lookup through all provider properties.
4. Introduce `DmtDataClient.get(Route, VcFetchRequest, Map<String,String>)`; inject it into ERL and implement it in `DmtApiClient`.
5. Extract endpoint-template validation, URI building, and limited response-body collection into focused classes. Preserve exact variable matching, origin/path validation, HTTPS, timeouts, no redirects, strict JSON parsing, status mapping, and cancellation.
6. Wire all beans explicitly in `DmtPluginConfiguration`, including HTTP client destruction. Update the README for package dependencies and the new strategy contract.

## Tests and acceptance

- Move existing tests to the relevant packages and share test fixtures instead of cross-test imports.
- Add fake-client tests for ERL lookup validation, route passing, response mismatch, and four-field mapping.
- Check route validation at startup, scope dispatch, multi-strategy extension, Spring bean selection, and client shutdown.
- Run `mvn -pl dmt-dataprovider-plugin -am clean verify -Dgpg.skip=true` and inspect the JAR package layout. The HTTPS tests require permission to bind a loopback server.

## Scope

Preserve existing local changes and avoid unrelated Certify, deployment, and parent-POM edits. The existing endpoint and token contract remain the basis for ERL; Driving License implementation is a separate feature.
