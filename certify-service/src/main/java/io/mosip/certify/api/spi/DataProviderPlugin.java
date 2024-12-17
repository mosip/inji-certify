package io.mosip.certify.api.spi;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import org.json.JSONObject;

import java.util.Map;

/**
 * DataProviderPlugin is implemented by VC plugin
 *  implementors who want to make use of the Certify to generate the VC.
 *  Data is fetched from a Plugin implementation, templated using {@link VCFormatter}
 *  and then signed using {@link VCSigner}.
 */
public interface DataProviderPlugin {
    JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException;
}
