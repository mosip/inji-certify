package lk.gov.dmt.certify.plugin;

import lk.gov.dmt.certify.plugin.application.ProviderRequestFactory;
import lk.gov.dmt.certify.plugin.application.VcDataFetcherRegistry;
import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.model.VcData;
import lk.gov.dmt.certify.plugin.model.VcFetchRequest;
import lk.gov.dmt.certify.plugin.spi.VcDataFetcher;
import lk.gov.dmt.certify.plugin.validation.DmtConfigurationValidator;
import lk.gov.dmt.certify.plugin.validation.EndpointTemplates;

import io.mosip.certify.api.spi.DataProviderPlugin;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.*;
import static lk.gov.dmt.certify.plugin.DmtTestFixtures.*;
import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

class DmtPluginTest {
    @Test
    void dispatchesSelectedScopeWithoutChangingClaims() throws Exception {
        var registry = new VcDataFetcherRegistry(VALID, List.of(fetcher("erl")));
        var claims = claims();
        var copy = new HashMap<>(claims);
        assertThat(new MasterDataProviderPlugin(registry, new ProviderRequestFactory()).fetchData(claims).getString("vehicleNo")).isEqualTo("ERL");
        assertThat(claims).isEqualTo(copy);
    }

    @Test
    void newStrategyRoutesWithoutDispatcherChanges() throws Exception {
        var extended = new DmtProviderProperties(true, VALID.clients(), Map.of("ERL", route("erl", "dmt_erl"),
                "DRIVING_LICENSE", route("driving-license", "dmt_driving_license")));
        var registry = new VcDataFetcherRegistry(extended, List.of(fetcher("erl"), fetcher("driving-license")));
        var claims = claims();
        claims.put(DataProviderPlugin.SELECTED_SCOPE, "dmt_driving_license");
        assertThat(new MasterDataProviderPlugin(registry, new ProviderRequestFactory()).fetchData(claims).getString("vehicleNo")).isEqualTo("DRIVING_LICENSE");
    }

    @Test
    void passesTheSelectedRegistrationRouteToItsFetcher() throws Exception {
        var erlRoute = route("shared", "dmt_erl");
        var licenseRoute = new DmtProviderProperties.Route(true, "shared", List.of("dmt_driving_license"),
                "dmt", "/licenses/{licenseNo}");
        var properties = new DmtProviderProperties(true, VALID.clients(), Map.of(
                "ERL", erlRoute, "DRIVING_LICENSE", licenseRoute));
        var passedRoute = new AtomicReference<DmtProviderProperties.Route>();
        VcDataFetcher shared = new VcDataFetcher() {
            public String strategyId() { return "shared"; }
            public VcData fetch(VcFetchRequest request, DmtProviderProperties.Route selectedRoute) {
                passedRoute.set(selectedRoute);
                return new VcData(Map.of("vehicleNo", request.vcType()));
            }
        };
        var claims = claims();
        claims.put(DataProviderPlugin.SELECTED_SCOPE, "dmt_driving_license");

        var plugin = new MasterDataProviderPlugin(new VcDataFetcherRegistry(properties, List.of(shared)),
                new ProviderRequestFactory());
        assertThat(plugin.fetchData(claims).getString("vehicleNo")).isEqualTo("DRIVING_LICENSE");
        assertThat(passedRoute.get()).isSameAs(licenseRoute);
    }

    @ParameterizedTest
    @ValueSource(strings = {"sub", "iss", "scope", "_certifySelectedScope"})
    void rejectsMissingOrNonStringClaims(String claim) {
        var plugin = new MasterDataProviderPlugin(new VcDataFetcherRegistry(VALID, List.of(fetcher("erl"))), new ProviderRequestFactory());
        var claims = claims();
        claims.remove(claim);
        assertThatThrownBy(() -> plugin.fetchData(claims)).isInstanceOf(ExchangeFailure.class);
        claims.put(claim, List.of("wrong-type"));
        assertThatThrownBy(() -> plugin.fetchData(claims)).isInstanceOf(ExchangeFailure.class);
    }

    @Test
    void rejectsUnauthorizedAndDisabledScopes() {
        var plugin = new MasterDataProviderPlugin(new VcDataFetcherRegistry(VALID, List.of(fetcher("erl"))), new ProviderRequestFactory());
        var claims = claims();
        claims.put(DataProviderPlugin.SELECTED_SCOPE, "not-in-token");
        assertThatThrownBy(() -> plugin.fetchData(claims)).isInstanceOf(ExchangeFailure.class);
        claims.put(DataProviderPlugin.SELECTED_SCOPE, "dmt_driving_license");
        assertThatThrownBy(() -> plugin.fetchData(claims)).isInstanceOf(ExchangeFailure.class);
    }

    @Test
    void rejectsDuplicateStrategiesMissingStrategiesAndDuplicateScopes() {
        assertThatThrownBy(() -> new VcDataFetcherRegistry(VALID, List.of(fetcher("erl"), fetcher("erl"))))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Duplicate strategy");
        assertThatThrownBy(() -> new VcDataFetcherRegistry(VALID, List.of()))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("missing strategy");
        var duplicate = new DmtProviderProperties(true, VALID.clients(), Map.of("ERL", route("erl", "dmt_erl"),
                "OTHER", route("other", "dmt_erl")));
        assertThatThrownBy(() -> new VcDataFetcherRegistry(duplicate, List.of(fetcher("erl"), fetcher("other"))))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Duplicate authorized scope");
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://dmt.example.gov.lk", "https://user:secret@dmt.example.gov.lk", "https://dmt.example.gov.lk?q=secret",
            "https://dmt.example.gov.lk/#fragment", "https://dmt.example.gov.lk/a/../b", "https://dmt.example.gov.lk/%0d%0a"})
    void rejectsUnsafeBaseUrls(String base) {
        assertThatThrownBy(() -> DmtConfigurationValidator.validate(properties(URI.create(base), Duration.ofSeconds(1), 1000)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://evil.example/{subject}", "//evil.example/{subject}", "/../{subject}", "/%2e%2e/{subject}",
            "/erl/{subject}?key=secret", "/erl/%0d%0a/{subject}", "/erl/{subject}/{subject}", "/erl/{invalid-name}"})
    void rejectsUnsafeEndpointPaths(String endpoint) {
        var bad = new DmtProviderProperties(true, VALID.clients(), Map.of("ERL",
                new DmtProviderProperties.Route(true, "erl", List.of("dmt_erl"), "dmt", endpoint)));
        assertThatThrownBy(() -> DmtConfigurationValidator.validate(bad)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsHeaderInjectionAndInvalidBoundsWithoutLeakingSecret() {
        var client = VALID.clients().get("dmt");
        var bad = new DmtProviderProperties(true, Map.of("dmt", new DmtProviderProperties.Client(client.baseUrl(),
                client.connectTimeout(), client.exchangeTimeout(), client.maxResponseBytes(), client.trustedIssuer(),
                new DmtProviderProperties.Authentication("X-Key", "secret\r\nInjected: true"))), VALID.vcTypes());
        assertThatThrownBy(() -> DmtConfigurationValidator.validate(bad)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("secret");
        assertThat(bad.toString()).doesNotContain("secret");
        assertThatThrownBy(() -> DmtConfigurationValidator.validate(properties(client.baseUrl(), Duration.ZERO, 100)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> DmtConfigurationValidator.validate(properties(client.baseUrl(), Duration.ofSeconds(1), 1048577)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void dataIsDefensivelyCopied() {
        var map = new HashMap<>(Map.of("vehicleNo", "original"));
        var data = new VcData(map);
        map.put("vehicleNo", "changed");
        assertThat(data.attributes()).containsEntry("vehicleNo", "original");
        assertThatThrownBy(() -> data.attributes().put("vehicleNo", "changed")).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> new VcData(Map.of("_holderId", "attacker"))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void copiesGenericLookupClaimForStrategies() throws Exception {
        var attributes = new HashMap<>(Map.of("vehicleNo", "WP-ABC-1234"));
        var claims = claims();
        claims.put("credential_lookup", attributes);
        VcDataFetcher strategy = new VcDataFetcher() {
            public String strategyId() { return "erl"; }
            public VcData fetch(VcFetchRequest request, DmtProviderProperties.Route route) {
                attributes.put("vehicleNo", "changed-after-handoff");
                assertThat(request.subject()).isEqualTo("subject-1");
                assertThat(request.lookupAttributes()).containsEntry("vehicleNo", "WP-ABC-1234");
                assertThatThrownBy(() -> request.lookupAttributes().put("vehicleNo", "changed"))
                        .isInstanceOf(UnsupportedOperationException.class);
                assertThat(request.toString()).doesNotContain("WP-ABC-1234");
                return new VcData(Map.of("vehicleNo", request.lookupAttributes().get("vehicleNo")));
            }
        };
        var plugin = new MasterDataProviderPlugin(new VcDataFetcherRegistry(VALID, List.of(strategy)), new ProviderRequestFactory());
        assertThat(plugin.fetchData(claims).getString("vehicleNo")).isEqualTo("WP-ABC-1234");
    }

    @Test
    void rejectsMalformedLookupClaimsWithoutDispatch() {
        VcDataFetcher neverCalled = new VcDataFetcher() {
            public String strategyId() { return "erl"; }
            public VcData fetch(VcFetchRequest request, DmtProviderProperties.Route route) { throw new AssertionError("Must not dispatch malformed lookup"); }
        };
        var plugin = new MasterDataProviderPlugin(new VcDataFetcherRegistry(VALID, List.of(neverCalled)), new ProviderRequestFactory());
        var claims = claims();
        var invalid = java.util.Arrays.asList(null, "WP-ABC-1234", Map.of("vehicleNo", 123),
                Map.of("vehicleNo", List.of("A")), Map.of("vehicleNo", " "), Map.of("vehicleNo", "A\r\nB"),
                Map.of("_holderId", "attacker"), Map.of(1, "vehicle"));
        for (Object value : invalid) {
            claims.put("credential_lookup", value);
            assertThatThrownBy(() -> plugin.fetchData(claims))
                    .isInstanceOfSatisfying(ExchangeFailure.class, e -> assertThat(e.failure()).isEqualTo(Failure.INVALID_LOOKUP));
        }
    }

    @Test
    void validatesGenericVariablesAndRejectsOldErlTemplate() {
        assertThat(EndpointTemplates.variables("/licenses/{licenseNo}/holders/{holderId}"))
                .containsExactlyInAnyOrder("licenseNo", "holderId");
        context().withPropertyValues("dmt.data-provider.vc-types[ERL].endpoint-path=/erl/{subject}")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    private ApplicationContextRunner context() {
        return new ApplicationContextRunner().withUserConfiguration(DmtPluginConfiguration.class)
                .withPropertyValues("mosip.certify.integration.data-provider-plugin=MasterDataProviderPlugin",
                        "dmt.data-provider.enabled=true", "dmt.data-provider.clients[dmt].base-url=https://dmt.example.gov.lk",
                        "dmt.data-provider.clients[dmt].connect-timeout=1s", "dmt.data-provider.clients[dmt].exchange-timeout=2s",
                        "dmt.data-provider.clients[dmt].max-response-bytes=65536",
                        "dmt.data-provider.clients[dmt].trusted-issuer=https://identity.example.gov.lk",
                        "dmt.data-provider.clients[dmt].authentication.api-key-header=X-API-Key",
                        "dmt.data-provider.clients[dmt].authentication.api-key=test-key",
                        "dmt.data-provider.vc-types[ERL].enabled=true", "dmt.data-provider.vc-types[ERL].strategy-id=erl",
                        "dmt.data-provider.vc-types[ERL].authorized-scopes[0]=dmt_erl", "dmt.data-provider.vc-types[ERL].client-id=dmt",
                        "dmt.data-provider.vc-types[ERL].endpoint-path=/api/v1/erl/vehicles/{vehicleNo}",
                        "dmt.data-provider.vc-types[DRIVING_LICENSE].enabled=false");
    }

    @Test
    void bindsPropertiesAndRegistersExactlyOneProvider() {
        context().run(ctx -> {
            assertThat(ctx).hasNotFailed().hasSingleBean(DataProviderPlugin.class);
            assertThat(ctx).hasSingleBean(lk.gov.dmt.certify.plugin.spi.DmtDataClient.class);
            assertThat(ctx.getBean(DmtProviderProperties.class).vcTypes()).containsKeys("ERL", "DRIVING_LICENSE");
        });
    }

    @Test
    void unselectedPluginDoesNotBindRequiredSecrets() {
        new ApplicationContextRunner().withUserConfiguration(DmtPluginConfiguration.class).run(ctx ->
                assertThat(ctx).hasNotFailed().doesNotHaveBean(DataProviderPlugin.class));
    }

    @Test
    void selectedDisabledProviderFailsStartup() {
        context().withPropertyValues("dmt.data-provider.enabled=false").run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void discoversAdditionalSpringStrategies() {
        context().withUserConfiguration(FutureConfiguration.class).withPropertyValues(
                "dmt.data-provider.vc-types[DRIVING_LICENSE].enabled=true",
                "dmt.data-provider.vc-types[DRIVING_LICENSE].strategy-id=driving-license",
                "dmt.data-provider.vc-types[DRIVING_LICENSE].authorized-scopes[0]=dmt_driving_license",
                "dmt.data-provider.vc-types[DRIVING_LICENSE].client-id=dmt",
                "dmt.data-provider.vc-types[DRIVING_LICENSE].endpoint-path=/licenses/{licenseNo}").run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx.getBean(VcDataFetcherRegistry.class).getRequired("DRIVING_LICENSE").fetcher().strategyId())
                            .isEqualTo("driving-license");
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class FutureConfiguration {
        @Bean VcDataFetcher drivingLicenseFetcher() { return fetcher("driving-license"); }
    }
}
