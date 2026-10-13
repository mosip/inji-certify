# Inji Certify: data integration implementation plan

Prepared for checkout `e54539a`, version `0.14.0`, on 2026-10-08. This is a guide and proposed implementation; no provider, database, credentials or running service were changed. See [code_explanation.md](code_explanation.md) for source paths and the request flow.

## Option 1: Direct Database Access Guide

### Fit and datasource constraint

Use the externally packaged PostgreSQL provider when the credential source can be made available in the same database as Certify. Local [development documentation](docs/Local-Development.md) verifies the plugin selector and query-map property. The [upstream README](https://github.com/inji/digital-credential-plugins/blob/master/postgres-dataprovider-plugin/README.md) describes a shared database, but the exact `0.6.0` implementation is absent from this checkout. Confirm it against the release source before rollout. No separate source-database URL/user/password properties were verified here.

Certify writes key/configuration/status/ledger data. **Do not replace its `spring.datasource` account with a globally read-only source account.** For the unmodified shared-database design, grant the existing application role SELECT on a narrow source view while retaining its application-schema write permissions. If policy requires an independently authenticated read-only source account or a separate database, extend/fork the provider with a dedicated, qualified datasource, or use Option 2. Treat that extension as additional implementation work, not as an existing plugin setting.

### Required settings and environment mapping

Create a private external profile, for example `config/application-registry.properties` (proposed file):

```properties
mosip.certify.plugin-mode=DataProvider
mosip.certify.integration.data-provider-plugin=PostgresDataProviderPlugin
# Set the actual component package from the pinned plugin source/JAR:
mosip.certify.integration.scan-base-package=${CERTIFY_SOURCE_PLUGIN_PACKAGE}
mosip.certify.data-provider-plugin.postgres.scope-query-mapping={'sample_vc_ldp':'select full_name as "fullName", date_of_birth::text as "dateOfBirth" from registry.credential_source where person_id=:id'}

# Certify application persistence, not an independently supported source pool:
spring.datasource.url=${CERTIFY_APP_JDBC_URL}
spring.datasource.username=${CERTIFY_APP_DB_USER}
spring.datasource.password=${CERTIFY_APP_DB_PASSWORD}
```

`CERTIFY_*` names above are proposed placeholder variables explicitly referenced by this file. Alternatively, Spring accepts `SPRING_DATASOURCE_URL`, `SPRING_DATASOURCE_USERNAME`, and `SPRING_DATASOURCE_PASSWORD` as environment overrides. Use a JDBC URL such as `jdbc:postgresql://db.example.internal:5432/inji_certify?currentSchema=certify&sslmode=verify-full` with trusted CA configuration for production. Keep secrets outside tracked properties. Configure authorization issuer/JWKS/audience, DID and key-manager settings using the existing environment's issuer setup as well; these plugin settings alone cannot start a complete issuer.

The named SQL parameter `:id` is documented as coming from the authenticated access-token `sub`. The credential configuration's scope and the authorization server's granted scope must both match `sample_vc_ldp`. Use explicit columns and quoted aliases to match template names exactly. Confirm output key casing with the pinned plugin. Parameterize values; never interpolate request claims into SQL identifiers or query strings. Use a unique indexed identity column and define an explicit policy for missing or multiple rows.

### Read-only service-account onboarding checklist

1. Agree with the source owner which authenticated subject corresponds to a source record. Do not assume an email or arbitrary `sub` is a national ID. Document issuer/tenant boundaries.
2. Create a view exposing only allowed credential attributes. Example SQL, executed by the registry owner in a disposable or approved database:

   ```sql
   CREATE SCHEMA IF NOT EXISTS registry;
   CREATE TABLE registry.people (
       person_id text PRIMARY KEY,
       full_name text NOT NULL,
       date_of_birth date NOT NULL
   );
   CREATE VIEW registry.credential_source AS
       SELECT person_id, full_name, date_of_birth FROM registry.people;
   CREATE ROLE certify_source_reader LOGIN;
   GRANT CONNECT ON DATABASE inji_certify TO certify_source_reader;
   GRANT USAGE ON SCHEMA registry TO certify_source_reader;
   GRANT SELECT ON registry.credential_source TO certify_source_reader;
   ALTER ROLE certify_source_reader SET default_transaction_read_only = on;
   ALTER ROLE certify_source_reader SET statement_timeout = '3s';
   ```

3. Set the role password through a protected administrative session (for example psql `\password certify_source_reader`) and store it in the deployment secret manager. SQL above intentionally does not embed a password. Verify inherited and PUBLIC privileges; do not grant owner/superuser/DDL/base-table rights to this reader. Read-only transaction defaults supplement object grants; they do not replace them.
4. Restrict network access and PostgreSQL authentication to the issuer/source connector; require TLS and certificate validation. Review view ownership and any tenant/RLS requirements with the source owner.
5. Choose the deployment route explicitly: shared datasource means granting `SELECT` on the view to the **actual Certify application role**, not configuring the separate reader; dedicated datasource means implementing a pool using the reader account with distinct property names, `@Qualifier`, read-only transactions and bounded pool/query timeouts. Preserve the application datasource as primary and test JPA/key-manager binding. Do not accidentally replace its bean.
6. As the reader, verify SELECT works; UPDATE/INSERT/DELETE/DDL fail; unauthorized source columns/tables remain inaccessible. As the actual application role, verify its application writes still succeed and its source access is limited to the approved view.
7. Install/pin `io.inji.certify:postgres-dataprovider-plugin:0.6.0`; inspect its package, selection annotations, datasource binding, scope parsing, no-row behavior and dependency compatibility. Derive the scan package from source or `jar tf postgres-dataprovider-plugin-0.6.0.jar`, not from the class name alone.
8. Add the query mapping, register a credential configuration, restart and issue one known credential. Measure query time and confirm identities cannot retrieve each other's data. Test a token containing several scopes because the SPI receives the whole scope string.

### Credential/template mapping shared by both options

Use the field names in [CredentialConfigurationDTO.java](certify-core/src/main/java/io/mosip/certify/core/dto/CredentialConfigurationDTO.java), not the older `context`/`credentialType` examples. Base the payload on [farmer-local-config.json](certify-service/src/main/resources/credential-configurations/farmer-local-config.json), replacing business attributes and contexts deliberately. Supply:

- `credentialConfigKeyId`, `credentialFormat: "ldp_vc"`, `scope: "sample_vc_ldp"`;
- `contextURLs`, `credentialTypes`, `metaDataDisplay`, `credentialSubjectDefinition`, `displayOrder`;
- `vcTemplate`: Base64 of UTF-8 Velocity template;
- `didUrl`, `keyManagerAppId`, `keyManagerRefId`, `signatureAlgo`, `signatureCryptoSuite` matching onboarded issuer keys.

Illustrative template fragment for the two mapped fields:

```velocity
"credentialSubject": {
  "id": "${_holderId}",
  "fullName": "$_esc.java($fullName)",
  "dateOfBirth": "$_esc.java($dateOfBirth)"
}
```

Embed this in a complete VC template with the approved context/types, `_issuer`, `validFrom` and `validUntil`. This uses Velocity's supplied escape tool; validate generated JSON with quotes, backslashes, newlines, control characters and Unicode. Do not assume raw `${fullName}` is safe JSON escaping. The source identity (`sub`) and holder's proof key (`_holderId`) have different meanings.

Create/update configuration at `/v1/certify/credential-configurations` with an authorized admin request, then inspect `/v1/certify/.well-known/openid-credential-issuer`. Keep configuration templates trusted and reviewed. Avoid changing global plugin properties through `pluginConfigurations`: automatic dispatch to `fetchData` was not found.

## Option 2: Custom API Data Fetcher Plugin Guide

### Contract, authorization and registration

Implement `io.mosip.certify.api.spi.DataProviderPlugin`:

```java
JSONObject fetchData(Map<String, Object> identityDetails)
    throws DataProviderExchangeException;
```

Java 21 is the repository baseline. Kotlin implementations must override the same JVM signature, return `JSONObject`, and package the compatible Kotlin runtime if needed. The SPI has no signing methods: Certify continues to format and sign the returned attributes.

The proposed API contract is `GET {base-url}/people/{encoded-sub}` returning `{"id":"...","fullName":"...","dateOfBirth":"YYYY-MM-DD"}`. The registry must authorize the service token for this operation; the plugin uses the authenticated `sub` only after validating the credential scope. For multiple upstream issuers/tenants, add an explicit trusted issuer-to-registry identity mapping before deployment. Do not forward the wallet token automatically.

### Production-oriented Java boilerplate

Proposed file: `registry-api-plugin/src/main/java/io/mosip/certify/registry/integration/RegistryApiDataProviderPlugin.java`. This is a new standalone plugin project, not an existing class. It uses one reusable JDK HTTP client, connection/request deadlines, no redirects, a bounded response subscriber, allowlisted output, service authentication, schema checks and sanitized checked exceptions. It deliberately performs one request per fetch; add bounded retries/circuit breaking only after defining the upstream's error and availability policy.

```java
package io.mosip.certify.registry.integration;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.api.util.ErrorConstants;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

@Component
@ConditionalOnProperty(name = "mosip.certify.integration.data-provider-plugin",
    havingValue = "RegistryApiDataProviderPlugin")
public final class RegistryApiDataProviderPlugin implements DataProviderPlugin {
    private static final int MAX_BODY = 65_536;
    private final HttpClient client;
    private final URI base;
    private final String token;
    private final String requiredScope;

    public RegistryApiDataProviderPlugin(
        @Value("${registry.api.base-url}") String url,
        @Value("${registry.api.service-token}") String token,
        @Value("${registry.api.required-scope:sample_vc_ldp}") String scope,
        @Value("${registry.api.allow-local-http:false}") boolean allowLocalHttp) {
        base = URI.create(url);
        boolean loopbackHttp = allowLocalHttp && "http".equals(base.getScheme())
            && List.of("localhost", "127.0.0.1").contains(base.getHost());
        if ((!"https".equals(base.getScheme()) && !loopbackHttp)
            || base.getHost() == null || base.getUserInfo() != null
            || base.getQuery() != null || base.getFragment() != null
            || !url.endsWith("/")) {
            throw new IllegalArgumentException("Invalid registry API base URL");
        }
        if (token == null || token.isBlank() || token.contains("\r")
            || token.contains("\n") || scope == null || scope.isBlank()) {
            throw new IllegalArgumentException("Invalid registry API authentication settings");
        }
        this.token = token;
        requiredScope = scope;
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    @Override
    public JSONObject fetchData(Map<String, Object> claims)
        throws DataProviderExchangeException {
        Object subject = claims == null ? null : claims.get("sub");
        Object scopes = claims == null ? null : claims.get("scope");
        if (!(subject instanceof String id) || id.isBlank() || id.length() > 256
            || !(scopes instanceof String scopeString)
            || Arrays.stream(scopeString.split("\\s+")).noneMatch(requiredScope::equals)) {
            throw failure("Invalid registry lookup claims");
        }
        // Encode the identity as one path segment; the origin comes from trusted config.
        String segment = URLEncoder.encode(id, StandardCharsets.UTF_8).replace("+", "%20");
        HttpRequest request = HttpRequest.newBuilder(base.resolve("people/" + segment))
            .timeout(Duration.ofSeconds(5))
            .header("Accept", "application/json")
            .header("Authorization", "Bearer " + token).GET().build();
        try {
            HttpResponse<byte[]> response = client.send(request, info -> new LimitedBody());
            if (response.statusCode() == 404) throw failure("Registry record unavailable");
            if (response.statusCode() == 401 || response.statusCode() == 403)
                throw failure("Registry service authorization failed");
            if (response.statusCode() == 429 || response.statusCode() >= 500)
                throw failure("Registry temporarily unavailable");
            if (response.statusCode() != 200) throw failure("Unexpected registry response");
            String mediaType = response.headers().firstValue("Content-Type").orElse("")
                .split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
            if (!mediaType.equals("application/json")) throw failure("Invalid registry media type");
            JSONObject record = new JSONObject(new String(response.body(), StandardCharsets.UTF_8));
            if (!id.equals(record.opt("id"))) throw failure("Registry identity mismatch");
            Object nameValue = record.opt("fullName");
            Object birthValue = record.opt("dateOfBirth");
            if (!(nameValue instanceof String name) || name.isBlank() || name.length() > 200
                || !(birthValue instanceof String birth) || birth.length() != 10) {
                throw failure("Invalid registry record fields");
            }
            LocalDate.parse(birth);
            // Never return arbitrary upstream keys: they could override template settings.
            return new JSONObject().put("fullName", name).put("dateOfBirth", birth);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw failure("Registry lookup interrupted");
        } catch (IOException e) {
            throw failure("Registry transport failure");
        } catch (RuntimeException e) {
            throw failure("Invalid registry response data");
        }
    }

    private static DataProviderExchangeException failure(String message) {
        return new DataProviderExchangeException(ErrorConstants.VCI_DATAFETCH_FAILED, message);
    }

    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private Flow.Subscription subscription;
        @Override public CompletionStage<byte[]> getBody() { return body; }
        @Override public void onSubscribe(Flow.Subscription s) {
            subscription = s;
            s.request(1);
        }
        @Override public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (buffer.remaining() > MAX_BODY - bytes.size()) {
                    subscription.cancel();
                    body.completeExceptionally(new IOException("Registry response too large"));
                    return;
                }
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                bytes.writeBytes(chunk);
            }
            subscription.request(1);
        }
        @Override public void onError(Throwable error) { body.completeExceptionally(error); }
        @Override public void onComplete() { body.complete(bytes.toByteArray()); }
    }
}
```

Before deployment, replace the static token property with the organization's rotation-capable service credential mechanism (OAuth client credentials, mounted rotating secret, or mTLS), configure trusted upstream CA certificates, and restrict egress to the registry. Configure concurrency limits to match registry capacity and record latency/failure metrics without subject data, tokens or response bodies. The boilerplate's error strings never include upstream bodies or credentials. Test it against the actual API contract and dependency set; it has not been compiled or integration-tested as part of this documentation task.

### Maven build and plugin registration

Create `registry-api-plugin/pom.xml` with a plain JAR (do not Spring Boot repackage the plugin). This example inherits dependency versions from the exact Certify parent and marks host-owned classes as provided:

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>io.inji.certify</groupId>
    <artifactId>certify-parent</artifactId>
    <version>0.14.0</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <groupId>io.mosip.certify.registry</groupId>
  <artifactId>registry-api-plugin</artifactId>
  <version>1.0.0</version>
  <properties><maven.compiler.release>21</maven.compiler.release></properties>
  <dependencies>
    <dependency>
      <groupId>io.inji.certify</groupId>
      <artifactId>certify-integration-api</artifactId>
      <version>0.14.0</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-autoconfigure</artifactId>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-context</artifactId>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>
```

The API's transitive JSON dependency is used here; confirm `org.json` is available on the compile and host classpaths. Build with Java 21 and Maven installed; this checkout has `mvnw.cmd` but no Unix `mvnw` script. Commands from the repository root, once the proposed files exist:

```bash
mvn -pl certify-integration-api -am install -DskipTests -Dgpg.skip=true
mvn -f registry-api-plugin/pom.xml clean package -Dgpg.skip=true
mvn -pl certify-service -am package -DskipTests -Dgpg.skip=true
mkdir -p local-plugins
cp registry-api-plugin/target/registry-api-plugin-1.0.0.jar local-plugins/
```

These packaging commands skip the existing service tests; they are not verification commands. Add plugin unit/integration tests before adoption. If adding new third-party runtime libraries, provide compatible thin dependency JARs alongside the plugin or shade/relocate them deliberately; do not bundle duplicate Spring/SPI classes.

Configure an external `application-registry.properties`:

```properties
mosip.certify.plugin-mode=DataProvider
mosip.certify.integration.scan-base-package=io.mosip.certify.registry.integration
mosip.certify.integration.data-provider-plugin=RegistryApiDataProviderPlugin
registry.api.base-url=${REGISTRY_API_BASE_URL}
registry.api.service-token=${REGISTRY_API_SERVICE_TOKEN}
registry.api.required-scope=sample_vc_ldp
registry.api.allow-local-http=false
```

Launch the actual packaged service JAR using JVM options before `-jar` (replace the example artifact name if the build differs):

```bash
java -Dloader.path="$PWD/local-plugins" -jar certify-service/target/certify-service-0.14.0.jar --spring.profiles.active=local,registry --spring.config.additional-location=file:./config/ --spring.cloud.config.enabled=false
```

The `local` profile in this command is for loopback development only. It disables real access-token validation through a debug filter. Use production profiles and real authentication outside that setting. For Docker, mount the plugin into the configured `loader_path_env` directory and supply equivalent properties/secrets. Confirm the effective image entrypoint, paths and JVM arguments rather than assuming shell expansion inside Docker JSON arguments. For an IDE launch, add the plugin as a runtime Maven dependency or explicitly add its JAR to the run classpath; `loader.path` does not extend an ordinary IDE main-class launch. Restart and verify exactly one `DataProviderPlugin` bean is selected.

## Decision Matrix

| Criterion | Option 1: PostgreSQL provider | Option 2: custom registry API provider |
| --- | --- | --- |
| Effort | Low for approved data in the shared database; higher for a separate datasource/account extension. | Medium: implement contract, auth, deployment and failure tests. |
| Security | Needs DB connectivity and narrow source grants; application persistence still needs writes. Separate account isolation requires confirmed support or an extension. | Source DB stays behind registry authorization; service credentials and subject/tenant mapping must be protected. |
| Maintenance | SQL and view contracts track schema changes; pin the external plugin and JDBC dependencies. | HTTP contract/version and credential rotation management; registry can hide storage changes. |
| Performance | Usually fewer hops; indexed queries and bounded pools matter. | Additional network/API hop; upstream capacity and deadlines matter. Benchmark actual P95/P99 and load. |
| Best fit | A trusted shared DB boundary with stable views. | An existing supported registry API or requirement for separate security ownership. |

Choose based on the source owner's access model. Neither option is universally faster or safer. For a separately managed government registry with an existing supported API, Option 2 is the initial preference; for an approved local shared-schema integration, Option 1 is simpler.

## Local Testing & Verification

### Common issuer preparation

1. Use Java 21, Maven, PostgreSQL and optionally Docker. Initialize a **fresh local application database** with the actual [db_scripts/inji_certify](db_scripts/inji_certify) scripts and their documented deployment properties. Do not run initialization against an existing shared database without reviewing its scripts. Some old local properties still reference nonexistent `db_scripts/mosip_certify` paths.
2. Start from `application-local.properties`, override application JDBC settings, select one provider and its scan package, and disable the config server if testing entirely from files. Provide a writable local keystore path and retain the app's key-manager, cache and audit configuration. Inspect startup failures before making issuance calls.
3. Register a test credential configuration using the shared mapping instructions. Confirm a `201` create response and discovery at `http://localhost:8090/v1/certify/.well-known/openid-credential-issuer`. Admin authentication and CSRF rules still depend on `SecurityConfig` settings.
4. For a deterministic local provider lookup, use the existing local filter's fallback claims: `sub=user@inji.io`, `scope=sample_vc_ldp`, `client_id=demo-certify`. Its `TestBearer` branch calls `Jwt.withTokenValue(token).build()` without decoding claims, so do not rely on arbitrary test JWT claims being parsed. For other identities, exercise `fetchData` directly in plugin tests or use a properly configured non-local authorization server.
5. Holder proof validation still runs in local issuance. Adapt the request/proof-generation scripts in [the mock identity Postman collection](docs/postman-collections/inji-certify-with-mock-identity.postman_collection.json) and its environment to the local endpoint, requested contexts/types, client ID, audience and valid nonce returned by the issuance flow. Do not send an empty/dummy proof and expect successful issuance.

### PostgreSQL fixture and checks

1. In the disposable application DB, create the registry table/view from Option 1 and insert a matching subject:

   ```sql
   INSERT INTO registry.people VALUES ('user@inji.io', 'Local Example', DATE '1990-01-02');
   ```

2. Give the actual Certify application role SELECT on `registry.credential_source`. In a separate account-isolation test, connect as `certify_source_reader` and verify the narrow grants. Using psql with a protected `.pgpass` or interactive password prompt:

   ```bash
   psql -h localhost -U certify_source_reader -d inji_certify -c "SELECT full_name FROM registry.credential_source WHERE person_id='user@inji.io'"
   psql -h localhost -U certify_source_reader -d inji_certify -c "DELETE FROM registry.people WHERE person_id='user@inji.io'"
   ```

   First succeeds; second must fail. A successful deletion is a failed security test; fix grants before continuing.
3. Install the PostgreSQL JAR, set the mapping, launch and issue the configured VC. Check exact JSON property casing and rendered values. Use `EXPLAIN (ANALYZE, BUFFERS)` on fixture queries to verify indexed lookups without exposing real PII in logs.
4. Test missing identities, SQL timeout, disconnected DB, denied view access, multiple token scopes and attempted SQL metacharacters in a subject. Expect a controlled fetch/issuance failure with no credential on lookup errors. Confirm no partial or mismatched credential is signed.
5. With a dedicated datasource extension, additionally confirm source queries use the reader and application writes use the app account; verify pool exhaustion does not silently switch accounts.

### Mock API fixture and checks

For the proposed plugin, run this disposable Python mock on loopback in a second terminal (save as `mock_registry.py` outside deployment artifacts):

```python
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Registry(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer local-test-token':
            self.send_error(401)
            return
        if self.path != '/people/user%40inji.io':
            self.send_error(404)
            return
        payload = json.dumps({'id': 'user@inji.io', 'fullName': 'Local Example',
                              'dateOfBirth': '1990-01-02'}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *_):
        pass  # Do not log subject-bearing URLs.

ThreadingHTTPServer(('127.0.0.1', 9081), Registry).serve_forever()
```

```bash
python3 mock_registry.py
```

1. Set `REGISTRY_API_BASE_URL=http://127.0.0.1:9081/`, `REGISTRY_API_SERVICE_TOKEN=local-test-token`, and override `registry.api.allow-local-http=true` in the private local profile. The HTTP exception accepts loopback only. When Certify runs in a container, loopback refers to that container; use a colocated mock or a trusted HTTPS test endpoint rather than weakening the production origin policy.
2. Verify the mock responds, then start Certify with the new provider and issue the same test VC. Both options should yield the same business attributes under the same template, although IDs/timestamps/proofs can differ.
3. Add plugin tests calling `fetchData(Map.of("sub", "user@inji.io", "scope", "sample_vc_ldp"))` against an isolated mock and assert only `fullName`/`dateOfBirth` return. Test quotes/newlines/Unicode through full templating. Test absent scope/subject, wrong ID, invalid date, missing fields, malformed JSON, extra reserved fields, 401/403/404/429/500, redirect, delayed response, oversized body, media-type mismatch and interruption. Confirm deadlines/cancellation and no data leakage in errors.
4. Run the plugin's tests with `mvn -f registry-api-plugin/pom.xml test`. Existing service regression tests can be run from root with `mvn -pl certify-service -am test -Dgpg.skip=true` after dependencies/environment are available. Source tests include `CertifyIssuanceServiceImplTest`, `CredentialConfigControllerTest` and credential/formatter utilities; they do not replace new upstream contract tests.
5. Debug with breakpoints in the selected provider, `CertifyIssuanceServiceImpl.getCredential`, `getVerifiableCredential`, `VelocityTemplatingEngineImpl.format`, and `W3CJsonLD.addProof`. Missing provider bean indicates classpath/scan/conditional problems; invalid scope indicates token/metadata mismatch; invalid JSON indicates response/template escaping; signing failures indicate key references, suite or contexts.
6. Verify the signed credential against the issuer's published DID key and appropriate contexts with an independent verifier. Also run a non-local-profile issuance test with a real signed access token and holder proof; reject wrong issuer/audience, expired tokens and replay/nonce errors. Local fallback claims alone cannot validate authentication security.

### Acceptance and remaining verification

Accept an option when one authenticated subject yields exactly its approved attributes, lookup failures produce no credential, source write restrictions hold, the intended single plugin loads, and an independent verifier accepts the signature. Capture latency under representative load and confirm failures do not leak tokens/PII.

This task produced documentation only. No Maven build, database initialization, mock server, plugin compilation or issuance test was executed. The external PostgreSQL artifact's exact datasource and scope behavior, and the proposed Java boilerplate against real dependencies, remain implementation-time checks explicitly called out above.
