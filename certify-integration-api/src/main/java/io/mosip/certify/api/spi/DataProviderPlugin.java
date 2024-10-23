package io.mosip.certify.api.spi;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import org.json.JSONObject;

import java.util.Map;

/**
 * DataProviderPlugin is implemented by type#2 of identity plugin
 *  implementors to fetch data for Certify to template into a VC
 *  format of choice using {@link VCFormatter}.
 */
public interface DataProviderPlugin {
    JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException;
}
