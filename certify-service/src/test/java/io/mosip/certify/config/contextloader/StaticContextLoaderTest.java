package io.mosip.certify.config.contextloader;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.sun.net.httpserver.HttpServer;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;
import org.junit.jupiter.api.*;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class StaticContextLoaderTest {

    private HttpServer server;
    private int port;
    private AtomicInteger hits;
    private ExecutorService executor;

    @BeforeEach
    void startServer() throws Exception {
        hits = new AtomicInteger(0);

        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        executor = Executors.newCachedThreadPool();
        server.setExecutor(executor);

        // Valid JSON-LD context object
        server.createContext("/ctx", exchange -> {
            hits.incrementAndGet();
            byte[] body = "{\"@context\":{}}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/ld+json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });

        // Another valid context
        server.createContext("/ctx2", exchange -> {
            hits.incrementAndGet();
            byte[] body = "{\"@context\":{\"x\":\"y\"}}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/ld+json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });

        // Invalid JSON (array) to trigger "Context must be a JSON object"
        server.createContext("/array", exchange -> {
            hits.incrementAndGet();
            byte[] body = "[1,2,3]".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });

        // Redirect: /redirect-ok → /ctx (same host)
        server.createContext("/redirect-ok", exchange -> {
            hits.incrementAndGet();
            exchange.getResponseHeaders().add("Location", "/ctx");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        // Redirect: /redirect-external → http://evil.example.org/ctx (blocked host)
        server.createContext("/redirect-external", exchange -> {
            hits.incrementAndGet();
            exchange.getResponseHeaders().add("Location", "http://evil.example.org/ctx");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        // Redirect chain: /chain0 → /chain1 → /chain2 → /chain3 → /chain4 → /chain5 → /chain6
        // This creates 7 redirect hops, exceeding MAX_REDIRECTS (5)
        for (int hop = 0; hop <= 6; hop++) {
            final int next = hop + 1;
            server.createContext("/chain" + hop, exchange -> {
                hits.incrementAndGet();
                exchange.getResponseHeaders().add("Location", "/chain" + next);
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
            });
        }

        server.start();
        port = server.getAddress().getPort();
    }

    @AfterEach
    void stopServer() {
        if (server != null) server.stop(0);
        if (executor != null) executor.shutdownNow();
    }

    // ---------------- helpers ----------------

    private static JsonLdContextLoaderProperties baseProps() {
        JsonLdContextLoaderProperties props = new JsonLdContextLoaderProperties();
        props.getCache().setEnabled(true);
        props.getCache().setMaxEntries(256);
        props.getCache().setTtl(Duration.ofHours(24));

        props.getRemote().setEnabled(true);
        props.getRemote().setAllowUnknown(false);
        props.getRemote().setAllowedHosts(new LinkedHashSet<>());

        props.setContexts(new LinkedHashMap<>());
        return props;
    }

    private static JsonLdContextLoaderProperties.Context ctx(String resource, boolean preload, boolean cache) {
        JsonLdContextLoaderProperties.Context c = new JsonLdContextLoaderProperties.Context();
        c.setResource(resource);
        c.setPreload(preload);
        c.setCache(cache);
        return c;
    }

    private static Resource existingJson(String json) {
        return new ByteArrayResource(json.getBytes(StandardCharsets.UTF_8)) {
            @Override public boolean exists() { return true; }
        };
    }

    private static Resource nonExisting() {
        return new ByteArrayResource(new byte[0]) {
            @Override public boolean exists() { return false; }
        };
    }

    private static JsonObject docToJson(Document doc) {
        assertTrue(doc instanceof JsonDocument, "Expected JsonDocument");
        JsonDocument jd = (JsonDocument) doc;
        Optional<JsonStructure> content = jd.getJsonContent();
        assertTrue(content.isPresent(), "Expected JSON content");
        assertTrue(content.get() instanceof JsonObject, "Expected JsonObject");
        return (JsonObject) content.get();
    }

    // ---------------- tests ----------------

    @Test
    void loadDocument_nullUrl_throws() {
        JsonLdContextLoaderProperties props = baseProps();
        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        assertThrows(JsonLdError.class, () -> loader.loadDocument(null, new DocumentLoaderOptions()));
    }

    @Test
    void configuredContext_cacheHit_returnsFromCache() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();

        String iri = "https://example.org/a";
        props.getContexts().put(iri, ctx("classpath:/a.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/a.json")).thenReturn(existingJson("{\"@context\":{}}"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());
        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());

        // second call should not read again due to cache
        verify(rl, times(1)).getResource("classpath:/a.json");
    }

    @Test
    void cacheDisabled_loadsEveryTime() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        props.getCache().setEnabled(false);

        String iri = "https://example.org/a";
        props.getContexts().put(iri, ctx("classpath:/a.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/a.json")).thenReturn(existingJson("{\"@context\":{}}"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());
        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());

        verify(rl, times(2)).getResource("classpath:/a.json");
    }

    @Test
    void perEntryCacheFalse_doesNotCacheEvenIfGlobalCacheEnabled() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();

        String iri = "https://example.org/nocache";
        // per-entry cache disabled
        props.getContexts().put(iri, ctx("classpath:/nocache.json", false, false));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/nocache.json")).thenReturn(existingJson("{\"@context\":{}}"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());
        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());

        // should read twice because not cached per entry
        verify(rl, times(2)).getResource("classpath:/nocache.json");
    }

    @Test
    void ttlZero_meansNeverExpires() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        props.getCache().setTtl(Duration.ZERO);

        String iri = "https://example.org/ttl0";
        props.getContexts().put(iri, ctx("classpath:/ttl0.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/ttl0.json")).thenReturn(existingJson("{\"@context\":{}}"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());
        Thread.sleep(5);
        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());

        verify(rl, times(1)).getResource("classpath:/ttl0.json");
    }

    @Test
    void ttlNegative_branchResultsInNeverExpires_inCurrentImplementation() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        // Your loader checks "!ttl.isNegative()" before setting expiresAt => negative behaves as "no expiry"
        props.getCache().setTtl(Duration.ofMillis(-1));

        String iri = "https://example.org/ttln";
        props.getContexts().put(iri, ctx("classpath:/ttln.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/ttln.json")).thenReturn(existingJson("{\"@context\":{}}"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());
        Thread.sleep(5);
        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());

        verify(rl, times(1)).getResource("classpath:/ttln.json");
    }

    @Test
    void ttlExpiry_causesReload() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        props.getCache().setTtl(Duration.ofMillis(1));

        String iri = "https://example.org/ttl1";
        props.getContexts().put(iri, ctx("classpath:/ttl1.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/ttl1.json")).thenReturn(existingJson("{\"@context\":{}}"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());
        Thread.sleep(5);
        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());

        verify(rl, times(2)).getResource("classpath:/ttl1.json");
    }

    @Test
    void maxEntries_full_preventsCachingNewKey() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        props.getCache().setMaxEntries(1);

        String iri1 = "https://example.org/a";
        String iri2 = "https://example.org/b";

        props.getContexts().put(iri1, ctx("classpath:/a.json", false, true));
        props.getContexts().put(iri2, ctx("classpath:/b.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/a.json")).thenReturn(existingJson("{\"@context\":{}}"));
        when(rl.getResource("classpath:/b.json")).thenReturn(existingJson("{\"@context\":{}}"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        // fills cache with iri1
        loader.loadDocument(URI.create(iri1), new DocumentLoaderOptions());

        // cache is full => iri2 won't be cached
        loader.loadDocument(URI.create(iri2), new DocumentLoaderOptions());
        loader.loadDocument(URI.create(iri2), new DocumentLoaderOptions());

        verify(rl, times(1)).getResource("classpath:/a.json");
        verify(rl, times(2)).getResource("classpath:/b.json");
    }

    @Test
    void maxEntries_full_expiredEntriesPurged_allowsNewInsert() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        props.getCache().setMaxEntries(1);
        // 1ms TTL is too short under CI load: the second iri2 load can miss the cache
        // after expiry and reload the resource. Use a short but CI-safe window.
        props.getCache().setTtl(Duration.ofMillis(200));

        String iri1 = "https://example.org/a";
        String iri2 = "https://example.org/b";

        props.getContexts().put(iri1, ctx("classpath:/a.json", false, true));
        props.getContexts().put(iri2, ctx("classpath:/b.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/a.json")).thenReturn(existingJson("{\"@context\":{}}"));
        when(rl.getResource("classpath:/b.json")).thenReturn(existingJson("{\"@context\":{}}"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        // fills cache with iri1
        loader.loadDocument(URI.create(iri1), new DocumentLoaderOptions());

        // wait for iri1 to expire
        Thread.sleep(250);

        // cache is full but iri1 is expired => purge should free capacity for iri2
        loader.loadDocument(URI.create(iri2), new DocumentLoaderOptions());
        // second load of iri2 should come from cache (resource loaded only once)
        loader.loadDocument(URI.create(iri2), new DocumentLoaderOptions());

        verify(rl, times(1)).getResource("classpath:/a.json");
        verify(rl, times(1)).getResource("classpath:/b.json");
    }

    @Test
    void unknownContext_allowUnknownFalse_throws() {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(false);

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create("http://localhost:" + port + "/ctx"), new DocumentLoaderOptions()));
        assertEquals(0, hits.get(), "Should not hit remote server");
    }

    @Test
    void allowUnknownFalse_hostInAllowedHosts_fetchesRemote() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(false);
        props.getRemote().setAllowedHosts(Set.of("localhost"));

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        String u = "http://localhost:" + port + "/ctx";

        Document d1 = loader.loadDocument(URI.create(u), new DocumentLoaderOptions());
        assertTrue(docToJson(d1).containsKey("@context"));

        // second call should be served from cache
        Document d2 = loader.loadDocument(URI.create(u), new DocumentLoaderOptions());
        assertTrue(docToJson(d2).containsKey("@context"));
        assertEquals(1, hits.get(), "Second call should be served from cache");
    }

    @Test
    void allowUnknownFalse_hostNotInAllowedHosts_throws() {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(false);
        props.getRemote().setAllowedHosts(Set.of("other.example.org"));

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        String u = "http://localhost:" + port + "/ctx";

        JsonLdError err = assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(u), new DocumentLoaderOptions()));
        assertTrue(err.getMessage().contains("not in the allowed hosts list"),
                "Expected allowed-hosts error, got: " + err.getMessage());
        assertEquals(0, hits.get(), "Should not hit remote server");
    }

    @Test
    void unknownContext_allowUnknownTrue_fetchesRemote_andCachesResult() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(true);

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        String u = "http://localhost:" + port + "/ctx";

        Document d1 = loader.loadDocument(URI.create(u), new DocumentLoaderOptions());
        assertTrue(docToJson(d1).containsKey("@context"));

        Document d2 = loader.loadDocument(URI.create(u), new DocumentLoaderOptions());
        assertTrue(docToJson(d2).containsKey("@context"));

        assertEquals(1, hits.get(), "Second call should be served from cache");
    }

    @Test
    void configuredRemoteResource_remoteDisabled_throwsInValidateIfRemoteResource() {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setEnabled(false);
        props.getRemote().setAllowUnknown(false);

        String iri = "https://example.org/custom";
        // configured resource is remote
        props.getContexts().put(iri, ctx("https://www.w3.org/some.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(iri), new DocumentLoaderOptions()));
    }

    @Test
    void configuredRemoteResource_remoteEnabled_allowUnknownFalse_enforcesAllowlist() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setEnabled(true);
        props.getRemote().setAllowUnknown(false); // allowlist checks should apply in your current code

        // IMPORTANT: allow localhost since we use local test server
        props.getRemote().setAllowedHosts(Set.of("localhost"));

        String iri = "https://example.org/custom";
        String remoteResource = "http://localhost:" + port + "/ctx"; // served by your test server (200 OK)
        props.getContexts().put(iri, ctx(remoteResource, false, true));

        ResourceLoader rl = mock(ResourceLoader.class); // won't be used for remote URL in the refactor
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        Document d = loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());
        assertTrue(docToJson(d).containsKey("@context"));

        // Optional: ensure the remote endpoint was hit once and then cached
        loader.loadDocument(URI.create(iri), new DocumentLoaderOptions());
        assertEquals(1, hits.get(), "Second call should be served from cache");
    }



    @Test
    void configuredRemoteResource_allowlistBlocksHost_whenAllowUnknownFalse() {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setEnabled(true);
        props.getRemote().setAllowUnknown(false);

        // allow only w3id.org => blocks www.w3.org
        props.getRemote().setAllowedHosts(Set.of("w3id.org"));

        String iri = "https://example.org/custom";
        props.getContexts().put(iri, ctx("https://www.w3.org/remote.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(iri), new DocumentLoaderOptions()));
    }

    @Test
    void loadFromResource_missingResource_throws() {
        JsonLdContextLoaderProperties props = baseProps();
        String iri = "https://example.org/missing";
        props.getContexts().put(iri, ctx("classpath:/missing.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/missing.json")).thenReturn(nonExisting());

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(iri), new DocumentLoaderOptions()));
    }

    @Test
    void loadFromResource_jsonNotObject_throws() {
        JsonLdContextLoaderProperties props = baseProps();
        String iri = "https://example.org/array";
        props.getContexts().put(iri, ctx("classpath:/array.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/array.json")).thenReturn(existingJson("[1,2,3]"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(iri), new DocumentLoaderOptions()));
    }

    @Test
    void loadFromResource_ioException_wrappedAsJsonLdError() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        String iri = "https://example.org/ioe";
        props.getContexts().put(iri, ctx("classpath:/ioe.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);

        Resource bad = mock(Resource.class);
        when(bad.exists()).thenReturn(true);
        when(bad.getInputStream()).thenThrow(new IOException("boom"));
        when(rl.getResource("classpath:/ioe.json")).thenReturn(bad);

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        JsonLdError err = assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(iri), new DocumentLoaderOptions()));
        assertTrue(err.getMessage().contains("Failed to load context"));
    }

    @Test
    void preload_true_loadsAtStartup_preloadFalseDoesNot() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();

        String preloadIri = "https://example.org/preload";
        String lazyIri = "https://example.org/lazy";

        props.getContexts().put(preloadIri, ctx("classpath:/preload.json", true, true));
        props.getContexts().put(lazyIri, ctx("classpath:/lazy.json", false, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/preload.json")).thenReturn(existingJson("{\"@context\":{}}"));
        when(rl.getResource("classpath:/lazy.json")).thenReturn(existingJson("{\"@context\":{}}"));

        StaticContextLoader loader = new StaticContextLoader(props, rl);

        // preload should have read preload.json once already
        verify(rl, times(1)).getResource("classpath:/preload.json");
        verify(rl, never()).getResource("classpath:/lazy.json");

        // loading lazy triggers first read
        loader.loadDocument(URI.create(lazyIri), new DocumentLoaderOptions());
        verify(rl, times(1)).getResource("classpath:/lazy.json");
    }

    @Test
    void preload_failure_doesNotCrashConstructor() {
        JsonLdContextLoaderProperties props = baseProps();
        String iri = "https://example.org/preloadFail";
        props.getContexts().put(iri, ctx("classpath:/missing.json", true, true));

        ResourceLoader rl = mock(ResourceLoader.class);
        when(rl.getResource("classpath:/missing.json")).thenReturn(nonExisting());

        assertDoesNotThrow(() -> new StaticContextLoader(props, rl));
    }

    @Test
    void reflection_cover_remoteValidation_unsupportedScheme_branch() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        Method m = findAnyDeclaredMethod(loader.getClass(),
                "validateRemoteAllowed",
                "validateRemoteBasics",
                "validateIfRemoteResource");

        assertNotNull(m, "Could not find any remote validation method to reflect.");
        m.setAccessible(true);

        Exception ex = assertThrows(Exception.class, () -> m.invoke(loader, URI.create("ftp://example.org/x")));
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause instanceof JsonLdError);
    }

    private static Method findAnyDeclaredMethod(Class<?> clazz, String... names) {
        for (String n : names) {
            for (Method m : clazz.getDeclaredMethods()) {
                if (m.getName().equals(n) && m.getParameterCount() == 1 && m.getParameterTypes()[0] == URI.class) {
                    return m;
                }
            }
        }
        return null;
    }

    @Test
    void reflection_cover_extractJsonObject_nonJsonDocument_branch() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        Method m = StaticContextLoader.class.getDeclaredMethod("extractJsonObject", Document.class);
        m.setAccessible(true);

        Document fake = mock(Document.class); // not a JsonDocument
        Object result = m.invoke(loader, fake);
        assertNull(result);
    }

    // ---------------- redirect tests ----------------

    @Test
    void redirect_sameAllowedHost_followsAndReturnsDocument() throws Exception {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(true);
        props.getRemote().setAllowedHosts(Set.of("localhost"));

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        String u = "http://localhost:" + port + "/redirect-ok";
        Document doc = loader.loadDocument(URI.create(u), new DocumentLoaderOptions());
        assertTrue(docToJson(doc).containsKey("@context"));
    }

    @Test
    void redirect_toBlockedHost_throws() {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(false);
        props.getRemote().setAllowedHosts(Set.of("localhost"));

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        String u = "http://localhost:" + port + "/redirect-external";
        JsonLdError err = assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(u), new DocumentLoaderOptions()));
        assertTrue(err.getMessage().contains("not allowed"),
                "Expected host-not-allowed error, got: " + err.getMessage());
    }

    @Test
    void redirect_tooManyHops_throws() {
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(true);

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        String u = "http://localhost:" + port + "/chain0";
        JsonLdError err = assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(u), new DocumentLoaderOptions()));
        assertTrue(err.getMessage().contains("Too many redirects"),
                "Expected too-many-redirects error, got: " + err.getMessage());
    }

    @Test
    void redirect_allowUnknownTrue_redirectToUnlistedHost_throws() {
        // allowUnknown=true allows the initial URL from any host,
        // but redirect hops must still land on an allowedHost when the list is non-empty
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(true);
        props.getRemote().setAllowedHosts(Set.of("localhost"));

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        // /redirect-external redirects to http://evil.example.org/ctx
        String u = "http://localhost:" + port + "/redirect-external";
        JsonLdError err = assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(u), new DocumentLoaderOptions()));
        assertTrue(err.getMessage().contains("not allowed"),
                "Expected redirect-host-not-allowed error, got: " + err.getMessage());
    }

    @Test
    void maxRedirects_configurable_respectsLimit() {
        // The chain endpoint creates 7 hops (/chain0 → /chain1 → ... → /chain6).
        // Default maxRedirects=5 triggers "Too many redirects".
        // Setting maxRedirects=2 should also trigger the error (but at hop 2).
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(true);
        props.getRemote().setMaxRedirects(2);

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        String u = "http://localhost:" + port + "/chain0";
        JsonLdError err = assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(u), new DocumentLoaderOptions()));
        assertTrue(err.getMessage().contains("Too many redirects"),
                "Expected too-many-redirects error, got: " + err.getMessage());
        assertTrue(err.getMessage().contains("max 2"),
                "Expected max 2 in error message, got: " + err.getMessage());
    }

    @Test
    void maxRedirects_zero_noRedirectsAllowed() {
        // maxRedirects=0 means no redirects are followed at all.
        // /redirect-ok returns 302, which should trigger the error immediately.
        JsonLdContextLoaderProperties props = baseProps();
        props.getRemote().setAllowUnknown(true);
        props.getRemote().setAllowedHosts(Set.of("localhost"));
        props.getRemote().setMaxRedirects(0);

        ResourceLoader rl = mock(ResourceLoader.class);
        StaticContextLoader loader = new StaticContextLoader(props, rl);

        String u = "http://localhost:" + port + "/redirect-ok";
        JsonLdError err = assertThrows(JsonLdError.class, () ->
                loader.loadDocument(URI.create(u), new DocumentLoaderOptions()));
        assertTrue(err.getMessage().contains("Too many redirects"),
                "Expected too-many-redirects error, got: " + err.getMessage());
    }
}
