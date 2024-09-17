package io.mosip.certify.api.spi;


import java.util.Map;
/**
 * VCDataModelFormatter is a templating engine which takes @param templateInput and returns a templated VC.
 * Some implementations include
 * - VC 2.0 data model templating engine
 */
public interface VCFormatter {
    // TODO: Should it be changed to JSONObject?
    String format(Map<String, Object> templateInput, Map<String, Object> defaultSettings);
}