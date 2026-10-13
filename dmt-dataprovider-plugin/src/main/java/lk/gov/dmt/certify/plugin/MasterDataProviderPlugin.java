package lk.gov.dmt.certify.plugin;

import lk.gov.dmt.certify.plugin.application.ProviderRequestFactory;
import lk.gov.dmt.certify.plugin.application.VcDataFetcherRegistry;
import lk.gov.dmt.certify.plugin.model.VcData;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.DataProviderPlugin;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.UUID;

import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

public final class MasterDataProviderPlugin implements DataProviderPlugin {
    private static final Logger LOG = LoggerFactory.getLogger(MasterDataProviderPlugin.class);
    private final VcDataFetcherRegistry registry;
    private final ProviderRequestFactory requestFactory;

    public MasterDataProviderPlugin(VcDataFetcherRegistry registry, ProviderRequestFactory requestFactory) {
        this.registry = registry;
        this.requestFactory = requestFactory;
    }

    @Override
    public JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException {
        String correlationId = UUID.randomUUID().toString();
        long start = System.nanoTime();
        String type = "unresolved";
        String strategy = "unresolved";
        try {
            String selectedScope = requestFactory.selectedScope(identityDetails);
            var registration = registry.resolveByScope(selectedScope);
            type = registration.vcType();
            strategy = registration.route().strategyId();
            var request = requestFactory.create(type, selectedScope, identityDetails, correlationId);
            VcData data = registration.fetcher().fetch(request, registration.route());
            LOG.atInfo().addKeyValue("correlationId", correlationId).addKeyValue("vcType", type)
                    .addKeyValue("strategy", strategy).addKeyValue("durationMs", elapsed(start))
                    .addKeyValue("outcome", "success").log("DMT data fetch completed");
            return new JSONObject(data.attributes());
        } catch (DataProviderExchangeException exception) {
            String failure = exception instanceof ExchangeFailure categorized ? categorized.failure().name() : "STRATEGY_FAILURE";
            LOG.atWarn().addKeyValue("correlationId", correlationId).addKeyValue("vcType", type)
                    .addKeyValue("strategy", strategy).addKeyValue("durationMs", elapsed(start))
                    .addKeyValue("outcome", failure).log("DMT data fetch failed");
            throw exception;
        }
    }

    private static long elapsed(long start) { return (System.nanoTime() - start) / 1_000_000; }
}
