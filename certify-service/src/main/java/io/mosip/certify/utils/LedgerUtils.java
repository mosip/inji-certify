package io.mosip.certify.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import io.mosip.certify.config.IndexedAttributesConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.entity.attributes.CredentialStatusDetail;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Slf4j
@Component
public class LedgerUtils {

    @Autowired
    private IndexedAttributesConfig indexedAttributesConfig;

    /**
     * Process extracted values to handle complex types appropriately
     */
    public static String extractCredentialType(JSONObject jsonObject) {
        try {
            if(jsonObject.has(Constants.TYPE)) {
                Object typeObj = jsonObject.get(Constants.TYPE);
                if (typeObj instanceof org.json.JSONArray typeArray) {
                    List<String> types = new ArrayList<>();

                    // Extract all types from the array
                    for(int i = 0; i < typeArray.length(); i++) {
                        String type = typeArray.getString(i);
                        if(type != null && !type.trim().isEmpty()) {
                            types.add(type.trim());
                        }
                    }

                    if(!types.isEmpty()) {
                        // Sort the types and join with comma
                        Collections.sort(types);
                        return String.join(",", types);
                    }
                } else {
                    // Single type as string
                    String singleType = typeObj.toString().trim();
                    if(!singleType.isEmpty()) {
                        return singleType;
                    }
                }
            }
            return "VerifiableCredential";
        } catch (Exception e) {
            log.warn("Error extracting credential type, using default", e);
            return "VerifiableCredential";
        }
    }

    // Enhanced version with better complex field support
    public Map<String, Object> extractIndexedAttributes(JSONObject jsonObject) {
        Configuration jsonPathConfig = Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS);
        Map<String, Object> indexedAttributes = new HashMap<>();

        if(jsonObject == null) {
            return indexedAttributes;
        }

        Map<String, String> indexedMappings = indexedAttributesConfig.getIndexedMappings();
        if(indexedMappings.isEmpty()) {
            log.info("No indexed mappings configured, returning empty attributes");
            return indexedAttributes;
        }
        log.info("Indexed Mapping Found: {}", indexedMappings);

        String sourceJsonString = jsonObject.toString();
        for (Map.Entry<String, String> entry : indexedMappings.entrySet()) {
            String targetKey = entry.getKey();
            String pathsConfig = entry.getValue();
            String[] paths = pathsConfig.split("\\|");
            Object extractedValue = null;

            for (String jsonPath : paths) {
                jsonPath = jsonPath.trim();
                try {
                    extractedValue = JsonPath.using(jsonPathConfig).parse(sourceJsonString).read(jsonPath);
                    if (extractedValue != null) {
                        break; // Found a value, no need to check other fallback paths
                    }
                } catch (Exception e) {
                    log.warn("Error extracting value for path '{}' and key '{}': {}", jsonPath, targetKey, e.getMessage());
                }
            }

            if (extractedValue != null) {
                Object processedValue = processExtractedIndexedAttributes(extractedValue);
                if (processedValue != null) {
                    indexedAttributes.put(targetKey, processedValue);
                    log.info("Added processed value '{}' to indexed attributes under key '{}'", processedValue, targetKey);
                }
            } else {
                log.info("No value extracted for key '{}'; skipping indexing.", targetKey);
            }
        }
        return indexedAttributes;
    }

    private Object processExtractedIndexedAttributes(Object extractedValue) {
        if(extractedValue == null) {
            return null;
        }
        if (extractedValue instanceof List<?> list) {
            if (list.isEmpty()) {
                return null;
            }
            return list.size() == 1 ? list.get(0) : extractedValue;
        } else if (extractedValue instanceof String stringValue) {
            return stringValue.trim().isEmpty() ? null : stringValue;
        }

        return extractedValue;
    }

    public CredentialStatusDetail extractCredentialStatusDetails(JSONObject jsonObject) {
        JSONObject credentialStatus = jsonObject.optJSONObject("credentialStatus");
        if(credentialStatus == null) {
            return null;
        }

        CredentialStatusDetail credentialStatusDetail = new CredentialStatusDetail();
        credentialStatusDetail.setStatusValue(false);
        credentialStatusDetail.setStatusPurpose((String) credentialStatus.get("statusPurpose"));
        credentialStatusDetail.setStatusListIndex(Long.parseLong((String) credentialStatus.get("statusListIndex")));
        credentialStatusDetail.setStatusListCredentialId((String) credentialStatus.get("statusListCredential"));
        credentialStatusDetail.setCreatedTimes(System.currentTimeMillis());

        return credentialStatusDetail;
    }
}
