package io.mosip.certify.api.spi;

import io.mosip.certify.api.exception.DataProviderExchangeException;

import java.util.Map;

/**
 * DataProviderPlugin is implemented by type#2 of identity plugin
 *  implementors to fetch data for Certify to template into a VC
 *  format of choice using {@link VCFormatter}.
 */
public interface DataProviderPlugin {
    Map<String, Object> fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException;
}
