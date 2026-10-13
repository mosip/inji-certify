package lk.gov.dmt.certify.plugin;

import io.mosip.certify.api.spi.DataProviderPlugin;
import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.model.VcData;
import lk.gov.dmt.certify.plugin.model.VcFetchRequest;
import lk.gov.dmt.certify.plugin.spi.VcDataFetcher;

import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Shared input fixtures for the plugin's package-level tests. */
public final class DmtTestFixtures {
    private DmtTestFixtures() {}

    public static DmtProviderProperties properties(URI base, Duration timeout, int maxBytes) {
        return new DmtProviderProperties(true, Map.of("dmt", new DmtProviderProperties.Client(base,
                Duration.ofSeconds(1), timeout, maxBytes, "https://identity.example.gov.lk",
                new DmtProviderProperties.Authentication("X-API-Key", "test-key"))),
                Map.of("ERL", route("erl", "dmt_erl"), "DRIVING_LICENSE",
                        new DmtProviderProperties.Route(false, "driving-license", null, null, null)));
    }

    public static DmtProviderProperties.Route route(String strategy, String scope) {
        return new DmtProviderProperties.Route(true, strategy, List.of(scope), "dmt", "/api/v1/erl/vehicles/{vehicleNo}");
    }

    public static VcDataFetcher fetcher(String id) {
        return new VcDataFetcher() {
            public String strategyId() { return id; }
            public VcData fetch(VcFetchRequest request, DmtProviderProperties.Route route) { return new VcData(Map.of("vehicleNo", request.vcType())); }
        };
    }

    public static Map<String, Object> claims() {
        return new HashMap<>(Map.of("scope", "openid dmt_erl dmt_driving_license", "sub", "subject-1",
                "iss", "https://identity.example.gov.lk", DataProviderPlugin.SELECTED_SCOPE, "dmt_erl",
                "credential_lookup", Map.of("vehicleNo", "WP-ABC-1234")));
    }

    public static final DmtProviderProperties VALID = properties(URI.create("https://dmt.example.gov.lk"), Duration.ofSeconds(2), 65536);

}
