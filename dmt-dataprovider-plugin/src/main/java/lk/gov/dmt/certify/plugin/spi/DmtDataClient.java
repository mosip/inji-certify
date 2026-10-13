package lk.gov.dmt.certify.plugin.spi;

import com.fasterxml.jackson.databind.JsonNode;
import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.ExchangeFailure;
import lk.gov.dmt.certify.plugin.model.VcFetchRequest;

import java.util.Map;

/** Retrieves an upstream document without exposing HTTP details to credential strategies. */
public interface DmtDataClient {
    JsonNode get(DmtProviderProperties.Route route, VcFetchRequest request,
                 Map<String, String> pathVariables) throws ExchangeFailure;
}
