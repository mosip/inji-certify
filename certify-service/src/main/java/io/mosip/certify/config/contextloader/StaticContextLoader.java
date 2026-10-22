package io.mosip.certify.config.contextloader;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonStructure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public final class StaticContextLoader implements DocumentLoader {

    private static final Logger log = LoggerFactory.getLogger(StaticContextLoader.class);

    private static final class CacheEntry {
        final JsonObject json;
        final long expiresAtMillis; // 0 = never expires
        CacheEntry(JsonObject json, long expiresAtMillis) {
            this.json = json;
            this.expiresAtMillis = expiresAtMillis;
        }
        boolean isExpired(long now) {
            return expiresAtMillis > 0 && now >= expiresAtMillis;
        }
    }

    private final JsonLdContextLoaderProperties jsonLdProps;
    private final ResourceLoader resourceLoader;
    private final HttpClient httpClient;

    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public StaticContextLoader(JsonLdContextLoaderProperties jsonLdProps, ResourceLoader resourceLoader) {
        this.jsonLdProps = jsonLdProps;
        this.resourceLoader = resourceLoader;

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        preloadConfiguredContexts();
    }

    @Override
    public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
        if (url == null) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, "Document URL is null.");
        }

        URI normalized = url.normalize();
        String iri = normalized.toString();

        // 1) Cache hit
        JsonObject cached = fetchCachedContext(iri);
        if (cached != null) {
            return JsonDocument.of(cached);
        }

        // 2) Configured mapping
        JsonLdContextLoaderProperties.Context configured = jsonLdProps.getContexts().get(iri);
        if (configured != null) {
            Document doc = loadFromResource(normalized, configured.getResource(), options);
            cacheDocument(iri, doc, configured.isCache());
            return doc;
        }

        // 3) Remote fetch for unmapped contexts
        if (!jsonLdProps.getRemote().isEnabled()) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "No configured mapping for context: " + iri + " and remote loading is disabled.");
        }

        // Allow if host is explicitly in allowedHosts, OR if allowUnknown is true
        if (!isHostAllowed(normalized) && !jsonLdProps.getRemote().isAllowUnknown()) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "No configured mapping for context: " + iri
                            + " and its host is not in the allowed hosts list.");
        }

        Document doc = fetchRemoteDocument(normalized);
        cacheDocument(iri, doc, true);
        return doc;
    }

    private void preloadConfiguredContexts() {
        jsonLdProps.getContexts().forEach((iri, cfg) -> {
            if (!cfg.isPreload()) return;
            try {
                Document doc = loadFromResource(URI.create(iri), cfg.getResource(), null);
                cacheDocument(iri, doc, cfg.isCache());
            } catch (Exception e) {
                log.warn("Failed to preload JSON-LD context {} from {}", iri, cfg.getResource(), e);
            }
        });
    }

    private Document loadFromResource(URI contextIri, String resourceLocation, DocumentLoaderOptions options) throws JsonLdError {
        if (resourceLocation == null || resourceLocation.isBlank()) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Blank resource location for context: " + contextIri);
        }

        // If resourceLocation is remote URL, load using remote policy
        if (isRemoteUrl(resourceLocation)) {
            if (!jsonLdProps.getRemote().isEnabled()) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Remote loading disabled, but configured context resource is remote: " + resourceLocation);
            }
            URI remoteUri = URI.create(resourceLocation).normalize();
            return fetchRemoteDocument(remoteUri);
        }

        // Local/classpath/file
        try {
            Resource resource = resourceLoader.getResource(resourceLocation);
            if (!resource.exists()) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Context resource does not exist: " + resourceLocation + " (for " + contextIri + ")");
            }

            try (InputStream is = resource.getInputStream();
                 JsonReader reader = Json.createReader(is)) {

                JsonStructure js = reader.read();
                if (!(js instanceof JsonObject obj)) {
                    throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                            "Context must be a JSON object at: " + resourceLocation + " (for " + contextIri + ")");
                }
                return JsonDocument.of(obj);
            }

        } catch (JsonLdError e) {
            throw e;
        } catch (Exception e) {
            JsonLdError wrapped = new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Failed to load context from " + resourceLocation + " (for " + contextIri + "): " + e.getMessage());
            wrapped.initCause(e);
            throw wrapped;
        }
    }

    private static JsonLdError fetchFailed(URI uri, Exception cause) {
        JsonLdError err = new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                "Failed to fetch remote context: " + uri + " - " + cause.getMessage());
        err.initCause(cause);
        return err;
    }

    /**
     * Fetches a remote JSON-LD document with manual redirect handling.
     * The initial request (i=0) is validated with {@link #validateRemoteHostAllowed},
     * which respects the {@code allowUnknown} setting.
     * Redirect hops (i>0) are validated with {@link #validateRedirectHostAllowed},
     * which always enforces {@code allowedHosts} regardless of {@code allowUnknown}.
     */
    private Document fetchRemoteDocument(URI uri) throws JsonLdError {
        URI current = uri;
        int maxRedirects = jsonLdProps.getRemote().getMaxRedirects();
        for (int i = 0; i <= maxRedirects; i++) {
            validateRemoteBasics(current);
            if (i == 0) {
                validateRemoteHostAllowed(current);
            } else {
                validateRedirectHostAllowed(current);
            }

            HttpResponse<String> response;
            try {
                response = httpClient.send(
                        HttpRequest.newBuilder(current).GET()
                                .timeout(Duration.ofSeconds(10))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
            } catch (InterruptedException e) {
                // Restore the flag so whoever is stopping this thread still sees the interrupt.
                Thread.currentThread().interrupt();
                throw fetchFailed(current, e);
            } catch (Exception e) {
                throw fetchFailed(current, e);
            }

            int status = response.statusCode();

            // Handle redirects (3xx)
            if (status >= 300 && status < 400) {
                URI redirectSource = current;
                String location = response.headers().firstValue("Location")
                        .orElseThrow(() -> new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                                "Redirect response with no Location header from: " + redirectSource));
                current = current.resolve(location);
                continue;
            }

            if (status != 200) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Remote context returned HTTP " + status + " for: " + current);
            }

            return parseJsonLdResponse(response.body(), uri);
        }

        throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                "Too many redirects (max " + maxRedirects + ") for remote context: " + uri);
    }

    private Document parseJsonLdResponse(String body, URI originalUri) throws JsonLdError {
        try (JsonReader reader = Json.createReader(new StringReader(body))) {
            JsonStructure js = reader.read();
            if (!(js instanceof JsonObject obj)) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Remote context must be a JSON object: " + originalUri);
            }
            return JsonDocument.of(obj);
        } catch (JsonLdError e) {
            throw e;
        } catch (Exception e) {
            JsonLdError err = new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Failed to parse remote context from " + originalUri + ": " + e.getMessage());
            err.initCause(e);
            throw err;
        }
    }

    private boolean isRemoteUrl(String resourceLocation) {
        String resourceUrl = resourceLocation.toLowerCase(Locale.ROOT);
        return resourceUrl.startsWith("http://") || resourceUrl.startsWith("https://");
    }

    private void validateRemoteBasics(URI uri) throws JsonLdError {
        String scheme = uri.getScheme();
        if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Unsupported scheme for remote context: " + uri);
        }
    }

    /**
     * Checks whether the URI's host is explicitly listed in the allowedHosts set.
     * Returns false if allowedHosts is empty (no positive trust signal).
     */
    private boolean isHostAllowed(URI uri) {
        Set<String> allowedHosts = jsonLdProps.getRemote().getAllowedHosts();
        if (allowedHosts == null || allowedHosts.isEmpty()) {
            return false;
        }
        String host = uri.getHost();
        if (host == null) return false;
        return allowedHosts.contains(host.toLowerCase(Locale.ROOT));
    }

    /**
     * Enforces host allowlist for the initial remote fetch request.
     * Skipped entirely when {@code allowUnknown=true} (open mode trusts all hosts
     * for the initial request).
     * When {@code allowUnknown=false}: if allowedHosts is non-empty, only listed hosts
     * are permitted; if allowedHosts is empty, no host restriction is applied.
     */
    private void validateRemoteHostAllowed(URI uri) throws JsonLdError {
        if (jsonLdProps.getRemote().isAllowUnknown()) {
            return; // open mode — all hosts trusted for initial request
        }

        Set<String> allowedHosts = jsonLdProps.getRemote().getAllowedHosts();
        if (allowedHosts == null || allowedHosts.isEmpty()) {
            return; // no restriction — allowedHosts not configured
        }

        String host = uri.getHost();
        if (host == null) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Remote context has no host: " + uri);
        }

        String normalizedHost = host.toLowerCase(Locale.ROOT);
        if (!allowedHosts.contains(normalizedHost)) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Remote context host not allowed: " + host + " (uri=" + uri + ")");
        }
    }

    /**
     * Enforces host allowlist on redirect hops. Unlike {@link #validateRemoteHostAllowed},
     * this is NOT bypassed by {@code allowUnknown=true}. Redirect targets must always
     * land on an allowed host when {@code allowedHosts} is configured (non-empty).
     * If {@code allowedHosts} is empty, no restriction is applied.
     */
    private void validateRedirectHostAllowed(URI uri) throws JsonLdError {
        Set<String> allowedHosts = jsonLdProps.getRemote().getAllowedHosts();
        if (allowedHosts == null || allowedHosts.isEmpty()) {
            return; // no restriction — allowedHosts not configured
        }

        String host = uri.getHost();
        if (host == null) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Redirect target has no host: " + uri);
        }

        String normalizedHost = host.toLowerCase(Locale.ROOT);
        if (!allowedHosts.contains(normalizedHost)) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Redirect target host not allowed: " + host + " (uri=" + uri + ")");
        }
    }

    private JsonObject fetchCachedContext(String iri) {
        if (!jsonLdProps.getCache().isEnabled()) return null;

        CacheEntry entry = cache.get(iri);
        if (entry == null) return null;

        long now = System.currentTimeMillis();
        if (entry.isExpired(now)) {
            cache.remove(iri, entry);
            return null;
        }
        return entry.json;
    }

    private void purgeExpiredEntries() {
        long now = System.currentTimeMillis();
        cache.forEach((key, entry) -> {
            if (entry.isExpired(now)) {
                cache.remove(key, entry);
            }
        });
    }

    private void cacheDocument(String iri, Document doc, boolean perEntryCache) {
        if (!jsonLdProps.getCache().isEnabled() || !perEntryCache) return;

        JsonObject json = extractJsonObject(doc);
        if (json == null) return;

        int maxEntries = jsonLdProps.getCache().getMaxEntries();
        if (maxEntries > 0 && cache.size() >= maxEntries && !cache.containsKey(iri)) {
            purgeExpiredEntries();
            if (cache.size() >= maxEntries && !cache.containsKey(iri)) {
                log.warn("Context cache full (maxEntries={}), not caching {}", maxEntries, iri);
                return;
            }
        }

        Duration ttl = jsonLdProps.getCache().getTtl();
        long expiresAt = 0L;
        if (ttl != null && !ttl.isZero() && !ttl.isNegative()) {
            expiresAt = System.currentTimeMillis() + ttl.toMillis();
        }

        cache.putIfAbsent(iri, new CacheEntry(json, expiresAt));
    }

    private JsonObject extractJsonObject(Document document) {
        if (!(document instanceof JsonDocument jd)) return null;
        Optional<JsonStructure> content = jd.getJsonContent();
        if (content.isEmpty()) return null;
        return (content.get() instanceof JsonObject jo) ? jo : null;
    }
}
