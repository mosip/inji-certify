package lk.gov.dmt.certify.plugin.transport;

import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.model.VcFetchRequest;
import lk.gov.dmt.certify.plugin.spi.DmtDataClient;
import lk.gov.dmt.certify.plugin.validation.DmtConfigurationValidator;
import lk.gov.dmt.certify.plugin.validation.TextValidation;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

/** HTTPS transport with no redirects, bounded body collection and a full exchange deadline. */
public final class DmtApiClient implements DmtDataClient, AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(DmtApiClient.class);
    private final DmtProviderProperties properties;
    private final Map<String, HttpClient> clients;
    private final ObjectMapper mapper = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    public DmtApiClient(DmtProviderProperties properties) {
        this(properties, createClients(properties));
    }

    // Package-private injection point for TLS-enabled transport tests.
    DmtApiClient(DmtProviderProperties properties, Map<String, HttpClient> clients) {
        DmtConfigurationValidator.validate(properties);
        this.properties = properties;
        this.clients = Map.copyOf(clients);
        for (String id : properties.clients().keySet()) {
            TextValidation.require(this.clients.containsKey(id)
                    && this.clients.get(id).followRedirects() == HttpClient.Redirect.NEVER,
                    "HTTP client must exist and disable redirects");
        }
    }

    private static Map<String, HttpClient> createClients(DmtProviderProperties properties) {
        DmtConfigurationValidator.validate(properties);
        Map<String, HttpClient> clients = new HashMap<>();
        properties.clients().forEach((id, config) -> clients.put(id, HttpClient.newBuilder()
                .connectTimeout(config.connectTimeout()).followRedirects(HttpClient.Redirect.NEVER).build()));
        return clients;
    }

    @Override
    public JsonNode get(DmtProviderProperties.Route route, VcFetchRequest request,
                        Map<String, String> pathVariables) throws ExchangeFailure {
        var config = properties.clients().get(route.clientId());
        if (!config.trustedIssuer().equals(request.issuer())) throw error(Failure.IDENTITY_ISSUER_MISMATCH);
        URI uri = DmtRequestUriBuilder.requestUri(config.baseUrl(), route.endpointPath(), pathVariables);
        HttpRequest httpRequest = HttpRequest.newBuilder(uri).timeout(config.exchangeTimeout())
                .header("Accept", "application/json")
                .header(config.authentication().apiKeyHeader(), config.authentication().apiKey())
                .GET().build();
        long deadline = System.nanoTime() + config.exchangeTimeout().toNanos();
        CompletableFuture<HttpResponse<byte[]>> pending = clients.get(route.clientId())
                .sendAsync(httpRequest, info -> new LimitedBodySubscriber(config.maxResponseBytes()));
        try {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) throw new TimeoutException();
            HttpResponse<byte[]> response = pending.get(remaining, TimeUnit.NANOSECONDS);
            int status = response.statusCode();
            LOG.atInfo().addKeyValue("correlationId", request.correlationId())
                    .addKeyValue("vcType", request.vcType()).addKeyValue("upstreamStatus", status)
                    .log("DMT upstream response received");
            if (status == 404) throw error(Failure.NOT_FOUND);
            if (status == 401 || status == 403) throw error(Failure.UPSTREAM_AUTHENTICATION);
            if (status != 200) throw error(Failure.UPSTREAM_STATUS);
            String contentType = response.headers().firstValue("Content-Type").orElse("")
                    .split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
            if (!contentType.equals("application/json") && !contentType.matches("application/[a-z0-9!#$&^_.+-]+\\+json")) {
                throw error(Failure.INVALID_RESPONSE);
            }
            try {
                return mapper.readTree(response.body());
            } catch (java.io.IOException e) {
                // Parser exceptions can contain response values; do not retain them.
                throw error(Failure.INVALID_RESPONSE);
            }
        } catch (TimeoutException e) {
            throw error(Failure.TIMEOUT);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw error(Failure.INTERRUPTED);
        } catch (ExecutionException e) {
            for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
                if (cause instanceof ExchangeFailure failure) throw failure;
                if (cause instanceof java.net.http.HttpTimeoutException) throw error(Failure.TIMEOUT);
            }
            throw error(Failure.TRANSPORT, e.getCause());
        } finally {
            if (!pending.isDone()) pending.cancel(true);
        }
    }

    @Override
    public void close() { clients.values().forEach(HttpClient::shutdownNow); }

}
