package io.mosip.certify.services.spi;


import org.json.JSONObject;

import java.util.Map;
/**
 * VCDataModelFormatter is a templating engine which takes @param templateInput and returns a templated VC.
 * Some implementations include
 * - VC 1.0 & 2.0 data model templating engine using Velocity
 */
public interface VCFormatter {
    String format(JSONObject valueMap, Map<String, Object> templateSettings);
}