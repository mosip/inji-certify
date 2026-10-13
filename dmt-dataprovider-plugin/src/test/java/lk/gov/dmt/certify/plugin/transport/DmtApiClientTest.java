package lk.gov.dmt.certify.plugin.transport;

import lk.gov.dmt.certify.plugin.DmtTestFixtures;
import lk.gov.dmt.certify.plugin.MasterDataProviderPlugin;
import lk.gov.dmt.certify.plugin.application.ProviderRequestFactory;
import lk.gov.dmt.certify.plugin.application.VcDataFetcherRegistry;
import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.credential.erl.ErlDataFetcher;
import lk.gov.dmt.certify.plugin.model.VcFetchRequest;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.mosip.certify.api.spi.DataProviderPlugin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;
import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

class DmtApiClientTest {
    private HttpsServer server;
    private ExecutorService executor;
    private SSLContext tls;
    private DmtApiClient client;
    private DmtProviderProperties properties;
    private final AtomicInteger calls = new AtomicInteger();
    private volatile int status = 200;
    private volatile String contentType = "application/json";
    private volatile String payload = """
            {"vehicleNo":"WP-ABC-1234","chassisNo":"CHASSIS000001","issueDate":"2026-01-01","expireDate":"2026-12-31","_holderId":"ignored"}
            """;
    private volatile long headerDelayMs;
    private volatile long bodyDelayMs;
    private volatile String receivedPath;
    private volatile String receivedKey;

    @BeforeEach
    void setUp() throws Exception {
        char[] password = "test-only-password".toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var resource = getClass().getResourceAsStream("/test-server.p12.base64")) {
            store.load(new ByteArrayInputStream(Base64.getMimeDecoder().decode(resource.readAllBytes())), password);
        }
        var keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, password);
        var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(store);
        tls = SSLContext.getInstance("TLS");
        tls.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
        server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        executor = Executors.newCachedThreadPool();
        server.setExecutor(executor);
        server.createContext("/", exchange -> {
            calls.incrementAndGet();
            receivedPath = exchange.getRequestURI().getRawPath();
            receivedKey = exchange.getRequestHeaders().getFirst("X-API-Key");
            try {
                if (headerDelayMs > 0) Thread.sleep(headerDelayMs);
                exchange.getResponseHeaders().set("Content-Type", contentType);
                if (status == 302) exchange.getResponseHeaders().set("Location", "/redirected");
                exchange.sendResponseHeaders(status, 0);
                if (bodyDelayMs > 0) Thread.sleep(bodyDelayMs);
                exchange.getResponseBody().write(payload.getBytes(StandardCharsets.UTF_8));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (java.io.IOException ignored) {
                // Cancellation/size-limit tests intentionally close the connection.
            } finally {
                exchange.close();
            }
        });
        server.start();
        configure(Duration.ofSeconds(3), 65536);
    }

    private void configure(Duration timeout, int limit) {
        if (client != null) client.close();
        properties = DmtTestFixtures.properties(URI.create("https://localhost:" + server.getAddress().getPort() + "/base"), timeout, limit);
        client = new DmtApiClient(properties, Map.of("dmt", HttpClient.newBuilder().sslContext(tls)
                .connectTimeout(Duration.ofSeconds(1)).followRedirects(HttpClient.Redirect.NEVER).build()));
    }

    @AfterEach
    void tearDown() {
        if (client != null) client.close();
        if (server != null) server.stop(0);
        if (executor != null) executor.shutdownNow();
    }

    private VcFetchRequest request(String vehicleNo) {
        return new VcFetchRequest("ERL", "dmt_erl", "subject-1", "https://identity.example.gov.lk", "test-correlation",
                Map.of("vehicleNo", vehicleNo));
    }

    private com.fasterxml.jackson.databind.JsonNode get(String vehicleNo) throws ExchangeFailure {
        return client.get(properties.vcTypes().get("ERL"), request(vehicleNo), Map.of("vehicleNo", vehicleNo));
    }

    private void assertFailure(Failure failure) {
        assertThatThrownBy(() -> get("WP-ABC-1234"))
                .isInstanceOfSatisfying(ExchangeFailure.class, e -> assertThat(e.failure()).isEqualTo(failure));
    }

    @Test
    void fetchesErlThroughHttpsAndReturnsOnlyBusinessFields() throws Exception {
        var strategy = new ErlDataFetcher(client);
        var registry = new VcDataFetcherRegistry(properties, java.util.List.of(strategy));
        var output = new MasterDataProviderPlugin(registry, new ProviderRequestFactory()).fetchData(DmtTestFixtures.claims());
        assertThat(output.keySet()).containsExactlyInAnyOrder("vehicleNo", "chassisNo", "issueDate", "expireDate");
        assertThat(output.getString("vehicleNo")).isEqualTo("WP-ABC-1234");
        assertThat(receivedKey).isEqualTo("test-key");
        assertThat(receivedPath).isEqualTo("/base/api/v1/erl/vehicles/WP-ABC-1234");
    }

    @Test
    void encodesGenericPathVariableAsOneSegment() throws Exception {
        get("alice@example.lk");
        assertThat(receivedPath).endsWith("alice%40example.lk");
    }

    @ParameterizedTest
    @ValueSource(strings = {"..", ".", "../other", "%2e%2e", "alice?admin=true", "alice#fragment", "alice\r\nInjected:yes"})
    void rejectsUnsafePathValuesBeforeNetwork(String subject) {
        assertThatThrownBy(() -> get(subject)).isInstanceOf(ExchangeFailure.class);
        assertThat(calls).hasValue(0);
    }

    @Test
    void rejectsIssuerMismatchBeforeNetwork() {
        var request = new VcFetchRequest("ERL", "dmt_erl", "subject-1", "https://other-issuer.example", "test", Map.of("vehicleNo", "WP-ABC-1234"));
        assertThatThrownBy(() -> client.get(properties.vcTypes().get("ERL"), request, Map.of("vehicleNo", "WP-ABC-1234")))
                .isInstanceOfSatisfying(ExchangeFailure.class, e -> assertThat(e.failure()).isEqualTo(Failure.IDENTITY_ISSUER_MISMATCH));
        assertThat(calls).hasValue(0);
    }

    @Test
    void missingVehicleNumberCannotFallBackToSubjectOrOtherClaims() {
        var claims = DmtTestFixtures.claims();
        claims.remove("credential_lookup");
        claims.put("vehicleNo", "WP-ABC-1234");
        var strategy = new ErlDataFetcher(client);
        var plugin = new MasterDataProviderPlugin(new VcDataFetcherRegistry(properties, java.util.List.of(strategy)), new ProviderRequestFactory());
        assertThatThrownBy(() -> plugin.fetchData(claims))
                .isInstanceOfSatisfying(ExchangeFailure.class, e -> assertThat(e.failure()).isEqualTo(Failure.INVALID_LOOKUP));
        assertThat(calls).hasValue(0);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "../other", "ABC/123", "ABC%2F123", "ABC_123", " ABC-123", "ABC--123",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"})
    void rejectsInvalidVehicleNumbersBeforeNetwork(String vehicleNo) {
        assertThatThrownBy(() -> new ErlDataFetcher(client).fetch(request(vehicleNo), properties.vcTypes().get("ERL")))
                .isInstanceOfSatisfying(ExchangeFailure.class, e -> assertThat(e.failure()).isEqualTo(Failure.INVALID_LOOKUP));
        assertThat(calls).hasValue(0);
    }

    @Test
    void rejectsResponseForAnotherVehicle() {
        payload = payload.replace("WP-ABC-1234", "WP-OTHER-9999");
        assertThatThrownBy(() -> new ErlDataFetcher(client).fetch(request("WP-ABC-1234"), properties.vcTypes().get("ERL")))
                .isInstanceOfSatisfying(ExchangeFailure.class, e -> assertThat(e.failure()).isEqualTo(Failure.INVALID_RESPONSE));
        assertThat(calls).hasValue(1);
    }

    @Test
    void requiresExactlyTheConfiguredPathVariablesBeforeNetwork() {
        for (Map<String, String> values : java.util.List.of(Map.<String, String>of(),
                Map.of("subject", "subject-1"), Map.of("vehicleNo", "WP-ABC-1234", "extra", "unexpected"))) {
            assertThatThrownBy(() -> client.get(properties.vcTypes().get("ERL"), request("WP-ABC-1234"), values))
                    .isInstanceOfSatisfying(ExchangeFailure.class, e -> assertThat(e.failure()).isEqualTo(Failure.INVALID_LOOKUP));
        }
        assertThat(calls).hasValue(0);
    }

    @Test
    void expandsMultipleNamedVariablesWithoutUsingIdentityAsLookup() throws Exception {
        var uri = DmtRequestUriBuilder.requestUri(URI.create("https://dmt.example.gov.lk/base"),
                "/licenses/{licenseNo}/holders/{holderId}", Map.of("licenseNo", "DL-123", "holderId", "alice@example.lk"));
        assertThat(uri.toASCIIString()).isEqualTo("https://dmt.example.gov.lk/base/licenses/DL-123/holders/alice%40example.lk");
    }

    @Test
    void doesNotFollowRedirects() {
        status = 302;
        assertFailure(Failure.UPSTREAM_STATUS);
        assertThat(calls).hasValue(1);
    }

    @Test
    void rejectsUpstreamErrorsWithoutRetry() {
        status = 404;
        assertFailure(Failure.NOT_FOUND);
        status = 401;
        assertFailure(Failure.UPSTREAM_AUTHENTICATION);
        status = 503;
        assertFailure(Failure.UPSTREAM_STATUS);
        assertThat(calls).hasValue(3);
    }

    @Test
    void rejectsInvalidContentTypeAndMalformedJson() {
        contentType = "text/html";
        assertFailure(Failure.INVALID_RESPONSE);
        contentType = "application/json";
        payload = "{not-json:secret-value}";
        assertFailure(Failure.INVALID_RESPONSE);
        payload = "{} {}";
        assertFailure(Failure.INVALID_RESPONSE);
        payload = "{\"vehicleNo\":\"one\",\"vehicleNo\":\"two\"}";
        assertFailure(Failure.INVALID_RESPONSE);
    }

    @Test
    void capsStreamingResponseBody() {
        configure(Duration.ofSeconds(3), 16);
        assertFailure(Failure.RESPONSE_TOO_LARGE);
    }

    @Test
    void deadlineIncludesResponseBodyConsumption() {
        configure(Duration.ofMillis(700), 65536);
        bodyDelayMs = 3000;
        long start = System.nanoTime();
        assertFailure(Failure.TIMEOUT);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
    }

    @Test
    void deadlineIncludesResponseHeaders() {
        configure(Duration.ofMillis(700), 65536);
        headerDelayMs = 3000;
        assertFailure(Failure.TIMEOUT);
    }

    @ParameterizedTest
    @ValueSource(strings = {"[]", "{}", "{\"vehicleNo\":123}",
            "{\"vehicleNo\":\"A\",\"chassisNo\":\"B\",\"issueDate\":\"2026-02-30\",\"expireDate\":\"2026-12-31\"}",
            "{\"vehicleNo\":\"A\",\"chassisNo\":\"B\",\"issueDate\":\"2026-12-31\",\"expireDate\":\"2026-01-01\"}"})
    void rejectsInvalidErlResponses(String invalid) {
        payload = invalid;
        assertThatThrownBy(() -> new ErlDataFetcher(client).fetch(request("WP-ABC-1234"), properties.vcTypes().get("ERL")))
                .isInstanceOfSatisfying(ExchangeFailure.class, e -> assertThat(e.failure()).isEqualTo(Failure.INVALID_RESPONSE));
    }
}
