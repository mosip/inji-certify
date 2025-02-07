package io.mosip.certify.api.spi;


import java.util.List;
import java.util.Map;

import org.json.JSONObject;
/**
 * VCFormatter is a templating engine. This engine is responsible to keep track
 * of templates, their formats, signature keys and any other additional information.
 * Some implementations include
 * - VC data model templating engine
 */
public interface VCFormatter {
    // TODO: Should it be changed to JSONObject?
    String format(JSONObject templateInput, Map<String, Object> defaultSettings);
    String format(Map<String, Object> templateInput);
    String getProofAlgorithm(String templateName);
    String getDidUrl(String templateName);
    String getRefID(String templateName);
    String getAppID(String templateName);
    List<String> getSelectiveDisclosureInfo(String templateName);
}