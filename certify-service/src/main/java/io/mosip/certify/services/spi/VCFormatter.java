package io.mosip.certify.services.spi;


import org.json.JSONObject;

import java.util.Map;
/**
 * VCDataModelFormatter is a templating engine which takes @param templateInput and returns a templated VC.
 * Some implementations include
 * - VC 1.0 & 2.0 data model templating engine using Velocity
 */
public interface VCFormatter {
    /**
     * returns a templated VC as per the data in valueMap & some templateSettings
     * @param valueMap data provided by a {@link DataProviderPlugin} implementation.
     * @param templateSettings configurable tunables
     * @return a templated & unsigned VC
     */
    String format(JSONObject valueMap, Map<String, Object> templateSettings);

    /**
     * an internal method for VCFormatters to fetch a VC template as per the key
     *
     * @param key an identifier for a VC template
     * @return Template String against a @param key
     */
    String getTemplate(String key);
}