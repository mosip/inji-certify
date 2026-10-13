package lk.gov.dmt.certify.plugin.application;

import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.spi.VcDataFetcher;
import lk.gov.dmt.certify.plugin.validation.DmtConfigurationValidator;
import lk.gov.dmt.certify.plugin.validation.TextValidation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

public final class VcDataFetcherRegistry {
    public record Registration(String vcType, DmtProviderProperties.Route route, VcDataFetcher fetcher) {}
    private final Map<String, Registration> byScope;
    private final Map<String, Registration> byType;

    public VcDataFetcherRegistry(DmtProviderProperties properties, List<VcDataFetcher> fetchers) {
        DmtConfigurationValidator.validate(properties);
        Map<String, VcDataFetcher> strategies = new HashMap<>();
        for (VcDataFetcher fetcher : fetchers) {
            TextValidation.require(TextValidation.text(fetcher.strategyId()), "Missing strategy identifier");
            TextValidation.require(strategies.putIfAbsent(fetcher.strategyId(), fetcher) == null, "Duplicate strategy identifier");
        }
        Map<String, Registration> scopes = new HashMap<>();
        Map<String, Registration> types = new HashMap<>();
        properties.vcTypes().forEach((type, route) -> {
            if (!route.enabled()) return;
            VcDataFetcher fetcher = strategies.get(route.strategyId());
            TextValidation.require(fetcher != null, "Enabled route references a missing strategy");
            fetcher.validateRoute(route);
            Registration registration = new Registration(type, route, fetcher);
            types.put(type, registration);
            route.authorizedScopes().forEach(scope -> scopes.put(scope, registration));
        });
        byScope = Map.copyOf(scopes);
        byType = Map.copyOf(types);
    }

    public Registration resolveByScope(String scope) throws ExchangeFailure {
        Registration registration = byScope.get(scope);
        if (registration == null) throw error(Failure.UNSUPPORTED_ROUTE);
        return registration;
    }

    public Registration getRequired(String type) throws ExchangeFailure {
        Registration registration = byType.get(type);
        if (registration == null) throw error(Failure.UNSUPPORTED_ROUTE);
        return registration;
    }
}
