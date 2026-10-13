package lk.gov.dmt.certify.plugin.spi;

import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.model.VcData;
import lk.gov.dmt.certify.plugin.model.VcFetchRequest;

import io.mosip.certify.api.exception.DataProviderExchangeException;

/** Strategies are discovered as Spring beans; new types need no dispatcher changes. */
public interface VcDataFetcher {
    String strategyId();

    default void validateRoute(DmtProviderProperties.Route route) {}

    VcData fetch(VcFetchRequest request, DmtProviderProperties.Route route)
            throws DataProviderExchangeException;
}
