/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for parsing Verifiable Presentation data
 * Handles different VP formats including JWT, form data, and encrypted presentations
 */
@Slf4j
@Component
public class VpParsingUtil {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${mosip.certify.vp-parsing.auto-detection.enabled:true}")
    private boolean autoDetectionEnabled;

    /**
     * Parse VP presentation data and extract vp_token
     * 
     * @param vpPresentation The raw VP presentation data
     * @param responseMode The response mode (iar-post or iar-post.jwt)
     * @return Extracted vp_token
     */
    public String extractVpToken(String vpPresentation, String responseMode) {
        try {
            log.debug("Extracting vp_token from presentation with response_mode: {}", responseMode);
            
            if ("iar-post.jwt".equals(responseMode)) {
                // Handle encrypted JWT response
                return extractVpTokenFromJwt(vpPresentation);
            } else if ("iar-post".equals(responseMode)) {
                // Handle unencrypted form data response
                return extractVpTokenFromForm(vpPresentation);
            } else {
                // Default: try to parse as form data first, then JWT
                return extractVpTokenAuto(vpPresentation);
            }
            
        } catch (Exception e) {
            log.error("Failed to extract vp_token from presentation", e);
            throw new RuntimeException("Failed to extract vp_token from VP presentation: " + e.getMessage(), e);
        }
    }

    /**
     * Parse VP presentation data and extract presentation_submission
     * 
     * @param vpPresentation The raw VP presentation data
     * @param responseMode The response mode (iar-post or iar-post.jwt)
     * @param defaultDefinitionId Default definition ID if not found in presentation
     * @return Extracted or generated presentation_submission
     */
    public String extractPresentationSubmission(String vpPresentation, String responseMode, String defaultDefinitionId) {
        try {
            log.debug("Extracting presentation_submission from presentation with response_mode: {}", responseMode);
            
            if ("iar-post.jwt".equals(responseMode)) {
                // Handle encrypted JWT response
                return extractSubmissionFromJwt(vpPresentation, defaultDefinitionId);
            } else if ("iar-post".equals(responseMode)) {
                // Handle unencrypted form data response
                return extractSubmissionFromForm(vpPresentation, defaultDefinitionId);
            } else {
                // Default: try to parse as form data first, then JWT
                return extractSubmissionAuto(vpPresentation, defaultDefinitionId);
            }
            
        } catch (Exception e) {
            log.error("Failed to extract presentation_submission from presentation", e);
            throw new RuntimeException("Failed to extract presentation_submission from VP presentation: " + e.getMessage(), e);
        }
    }

    /**
     * Extract vp_token from JWT format
     */
    private String extractVpTokenFromJwt(String jwtPresentation) {
        try {
            // Try to parse as JSON containing JWT
            JsonNode jsonNode = objectMapper.readTree(jwtPresentation);
            if (jsonNode.has("response")) {
                return jsonNode.get("response").asText();
            }
            if (jsonNode.has("vp_token")) {
                return jsonNode.get("vp_token").asText();
            }
            
            // Return as-is if not in expected format
            return jwtPresentation;
        } catch (Exception e) {
            log.error("Failed to parse JWT presentation", e);
            throw new RuntimeException("Invalid JWT presentation format: " + e.getMessage(), e);
        }
    }

    /**
     * Extract vp_token from form data
     */
    private String extractVpTokenFromForm(String formPresentation) {
        try {
            // Parse URL-encoded form data
            Map<String, String> formData = parseFormData(formPresentation);
            
            if (formData.containsKey("vp_token")) {
                return formData.get("vp_token");
            }
            
            // Try parsing as JSON
            JsonNode jsonNode = objectMapper.readTree(formPresentation);
            if (jsonNode.has("vp_token")) {
                return jsonNode.get("vp_token").asText();
            }
            
            // Return as-is if not in expected format
            return formPresentation;
        } catch (Exception e) {
            log.error("Failed to parse form presentation", e);
            throw new RuntimeException("Invalid form presentation format: " + e.getMessage(), e);
        }
    }

    /**
     * Auto-detect format and extract vp_token
     * Uses configurable auto-detection settings
     */
    private String extractVpTokenAuto(String vpPresentation) {
        if (!autoDetectionEnabled) {
            log.debug("Auto-detection disabled, returning presentation as-is");
            return vpPresentation;
        }
        
        // Try form data first
        if (vpPresentation.contains("vp_token=") || vpPresentation.contains("\"vp_token\"")) {
            log.debug("Auto-detected form data format");
            return extractVpTokenFromForm(vpPresentation);
        }
        
        // Try JWT-like formats next (no validation here, just extraction attempts)
        if (vpPresentation.contains("response=") || vpPresentation.contains("\"response\"")) {
            log.debug("Auto-detected JWT-like format");
            return extractVpTokenFromJwt(vpPresentation);
        }

        // As a fallback, attempt JWT extraction; if it doesn't parse as JSON, it will return as-is
        log.debug("Attempting JWT extraction as fallback");
        return extractVpTokenFromJwt(vpPresentation);
    }

    /**
     * Extract presentation_submission from JWT
     */
    private String extractSubmissionFromJwt(String jwtPresentation, String defaultDefinitionId) {
        try {
            // Try to parse as JSON containing presentation_submission
            JsonNode jsonNode = objectMapper.readTree(jwtPresentation);
            if (jsonNode.has("presentation_submission")) {
                return jsonNode.get("presentation_submission").toString();
            }
            
            log.warn("No presentation_submission found in JWT for definition_id: {}, generating default", defaultDefinitionId);
            return generateDefaultPresentationSubmission(defaultDefinitionId);
            
        } catch (Exception e) {
            log.error("Failed to parse JWT for presentation_submission", e);
            throw new RuntimeException("Invalid JWT format for presentation_submission: " + e.getMessage(), e);
        }
    }

    /**
     * Extract presentation_submission from form data
     */
    private String extractSubmissionFromForm(String formPresentation, String defaultDefinitionId) {
        try {
            // Parse form data
            Map<String, String> formData = parseFormData(formPresentation);
            
            if (formData.containsKey("presentation_submission")) {
                return formData.get("presentation_submission");
            }
            
            // Try parsing as JSON
            JsonNode jsonNode = objectMapper.readTree(formPresentation);
            if (jsonNode.has("presentation_submission")) {
                return jsonNode.get("presentation_submission").toString();
            }
            
            log.error("No presentation_submission found in form data for definition_id: {}", defaultDefinitionId);
            throw new RuntimeException("No presentation_submission found in form presentation");
        } catch (Exception e) {
            log.error("Failed to parse form data for presentation_submission", e);
            throw new RuntimeException("Invalid form format for presentation_submission: " + e.getMessage(), e);
        }
    }

    /**
     * Auto-detect format and extract presentation_submission
     */
    private String extractSubmissionAuto(String vpPresentation, String defaultDefinitionId) {
        // Try form data first
        if (vpPresentation.contains("presentation_submission=") || vpPresentation.contains("\"presentation_submission\"")) {
            return extractSubmissionFromForm(vpPresentation, defaultDefinitionId);
        }
        
        // Try JWT
        return extractSubmissionFromJwt(vpPresentation, defaultDefinitionId);
    }

    /**
     * Parse URL-encoded form data into key-value map
     */
    private Map<String, String> parseFormData(String formData) {
        Map<String, String> result = new HashMap<>();
        
        if (!StringUtils.hasText(formData)) {
            return result;
        }
        
        try {
            String[] pairs = formData.split("&");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=", 2);
                if (keyValue.length == 2) {
                    String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                    result.put(key, value);
                }
            }
        } catch (Exception e) {
            log.debug("Failed to parse form data: {}", e.getMessage());
        }
        
        return result;
    }

    
    
    /**
     * Generate default presentation submission when not found in the presentation
     */
    private String generateDefaultPresentationSubmission(String defaultDefinitionId) {
        try {
            Map<String, Object> submission = new HashMap<>();
            submission.put("id", "default_submission_" + System.currentTimeMillis());
            submission.put("definition_id", StringUtils.hasText(defaultDefinitionId) ? defaultDefinitionId : "default");
            
            Map<String, Object> descriptorMap = new HashMap<>();
            descriptorMap.put("id", "default_identity");
            descriptorMap.put("format", "ldp_vp");
            descriptorMap.put("path", "$.verifiableCredential[0]");
            
            submission.put("descriptor_map", new Object[]{descriptorMap});
            
            return objectMapper.writeValueAsString(submission);
        } catch (Exception e) {
            log.error("Failed to generate default presentation submission", e);
            return "{\"id\":\"default_submission\",\"definition_id\":\"" + defaultDefinitionId + "\",\"descriptor_map\":[{\"id\":\"default_identity\",\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[0]\"}]}";
        }
    }
}
