package lk.gov.dmt.certify.plugin.credential.erl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.model.VcFetchRequest;
import lk.gov.dmt.certify.plugin.spi.DmtDataClient;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;
import static org.assertj.core.api.Assertions.*;

class ErlDataFetcherTest {
    private static final DmtProviderProperties.Route ROUTE = new DmtProviderProperties.Route(
            true, "erl", List.of("dmt_erl"), "dmt", "/api/v1/erl/vehicles/{vehicleNo}");

    private static VcFetchRequest request(Map<String, String> lookup) {
        return new VcFetchRequest("ERL", "dmt_erl", "subject-1", "https://identity.example.gov.lk",
                "correlation-1", lookup);
    }

    @Test
    void passesResolvedRouteAndReturnsOnlyAllowedFields() throws Exception {
        var client = new StubClient(new ObjectMapper().readTree("""
                {"vehicleNo":"WP-ABC-1234","chassisNo":"CHASSIS-1","issueDate":"2026-01-01",
                 "expireDate":"2026-12-31","internalNotes":"must not appear"}
                """));
        var fetcher = new ErlDataFetcher(client);
        var data = fetcher.fetch(request(Map.of("vehicleNo", "WP-ABC-1234")), ROUTE);

        assertThat(client.route).isSameAs(ROUTE);
        assertThat(client.pathVariables).containsExactly(entry("vehicleNo", "WP-ABC-1234"));
        assertThat(data.attributes()).containsOnlyKeys("vehicleNo", "chassisNo", "issueDate", "expireDate");
        assertThat(data.attributes()).containsEntry("chassisNo", "CHASSIS-1");
    }

    @Test
    void missingLookupFailsBeforeCallingClient() throws Exception {
        var client = new StubClient(new ObjectMapper().readTree("{}"));
        assertThatThrownBy(() -> new ErlDataFetcher(client).fetch(request(Map.of()), ROUTE))
                .isInstanceOfSatisfying(ExchangeFailure.class,
                        failure -> assertThat(failure.failure()).isEqualTo(Failure.INVALID_LOOKUP));
        assertThat(client.calls).isZero();
    }

    @Test
    void mismatchedResponseFails() throws Exception {
        var client = new StubClient(new ObjectMapper().readTree("""
                {"vehicleNo":"WP-OTHER-9999","chassisNo":"CHASSIS-1","issueDate":"2026-01-01",
                 "expireDate":"2026-12-31"}
                """));
        assertThatThrownBy(() -> new ErlDataFetcher(client)
                .fetch(request(Map.of("vehicleNo", "WP-ABC-1234")), ROUTE))
                .isInstanceOfSatisfying(ExchangeFailure.class,
                        failure -> assertThat(failure.failure()).isEqualTo(Failure.INVALID_RESPONSE));
        assertThat(client.calls).isEqualTo(1);
    }

    private static final class StubClient implements DmtDataClient {
        private final JsonNode response;
        private DmtProviderProperties.Route route;
        private Map<String, String> pathVariables;
        private int calls;

        private StubClient(JsonNode response) { this.response = response; }

        @Override
        public JsonNode get(DmtProviderProperties.Route route, VcFetchRequest request,
                            Map<String, String> pathVariables) {
            calls++;
            this.route = route;
            this.pathVariables = pathVariables;
            return response;
        }
    }
}
