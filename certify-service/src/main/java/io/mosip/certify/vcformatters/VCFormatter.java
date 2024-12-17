package io.mosip.certify.vcformatters;

import java.util.Map;

import org.json.JSONObject;
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
}