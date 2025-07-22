/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.vcformatters;

import java.io.StringWriter;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.tools.generic.DateTool;
import org.apache.velocity.tools.generic.EscapeTool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.cache.annotation.Cacheable;

import org.json.JSONArray;
import org.json.JSONObject;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.spi.RenderingTemplateService;
import io.mosip.certify.services.CredentialUtils;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import static io.mosip.certify.core.constants.Constants.*;

/**
 * MDocVCFormatter handles mDOC (Mobile Document) credential formatting.
 * This formatter processes templates with mDOC structure including:
 * - Namespaces organization
 * - DigestID assignment
 * - Element identifier mapping
 * - CBOR-compatible data structures
 *
 * The formatter works with Velocity templates that define mDOC structure
 * and prepares unsigned mDOC JSON that can be later signed with COSE.
 */
@Slf4j
@Service("mdocFormatter")
public class MDocVCFormatter implements VCFormatter{

    private VelocityEngine engine;

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private RenderingTemplateService renderingTemplateService;

    @Value("${mosip.certify.data-provider-plugin.vc-expiry-duration:P730d}")
    private String defaultExpiryDuration;

    @Value("${mosip.certify.data-provider-plugin.id-field-prefix-uri:}")
    private String idPrefix;

    @PostConstruct
    public void initialize() {
        engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        engine.init();
        log.info("MDocVCFormatter initialized. Using Spring Cache for CredentialConfig.");
    }

    /**
     * Internal method to fetch CredentialConfig, leveraging Spring Cache.
     * The key is expected to be "credentialType:context:credentialFormat".
     */
    @Cacheable(cacheNames = "credentialConfig", key = "#templateKey")
    protected CredentialConfig getCachedCredentialConfig(String templateKey) {
        log.debug("Cache miss for credentialConfig with key: {}. Fetching from DB.", templateKey);
        if (templateKey == null || !templateKey.contains(DELIMITER)) {
            log.error("Invalid templateKey format for getCachedCredentialConfig: {}", templateKey);
            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "Invalid template key format: " + templateKey);
        }

        String[] parts = templateKey.split(DELIMITER, 3);
        if (parts.length < 2) {
            log.error("Invalid templateKey format for getCachedCredentialConfig: {}. Expected at least 2 parts.", templateKey);
            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "Template key format requires at least 2 parts: " + templateKey);
        } else if (parts.length == 2) {
            String credentialFormat = parts[0];
            String vct = parts[1];

            return credentialConfigRepository.findByCredentialFormatAndSdJwtVct(credentialFormat, vct)
                    .orElseThrow(() -> {
                        log.error("CredentialConfig not found in DB for key: {}", templateKey);
                        return new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "CredentialConfig not found for key: " + templateKey);
                    });
        }

        String credentialType = parts[0];
        String context = parts[1];
        String credentialFormat = parts[2];

        return credentialConfigRepository
                .findByCredentialFormatAndCredentialTypeAndContext(credentialFormat, credentialType, context)
                .orElseThrow(() -> {
                    log.error("CredentialConfig not found in DB for key: {}", templateKey);
                    return new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "CredentialConfig not found for key: " + templateKey);
                });
    }

    @Override
    public String getProofAlgorithm(String templateName) {
        return getCachedCredentialConfig(templateName).getSignatureAlgo();
    }

    @Override
    public String getDidUrl(String templateName) {
        return getCachedCredentialConfig(templateName).getDidUrl();
    }

    @Override
    public String getRefID(String templateName) {
        return getCachedCredentialConfig(templateName).getKeyManagerRefId();
    }

    @Override
    public String getAppID(String templateName) {
        return getCachedCredentialConfig(templateName).getKeyManagerAppId();
    }

    @Override
    public List<String> getSelectiveDisclosureInfo(String templateName) {
        String sdClaimValue = getCachedCredentialConfig(templateName).getSdClaim();
        return Optional.ofNullable(sdClaimValue)
                .map(sd -> Arrays.asList(sd.split(",")))
                .orElseGet(ArrayList::new);
    }

    @SneakyThrows
    @Override
    public String format(JSONObject valueMap, Map<String, Object> templateSettings) {
        String templateName = templateSettings.get(TEMPLATE_NAME).toString();
        String issuer = templateSettings.get(ISSUER_URI).toString();

//        String vcTemplateString = getCachedCredentialConfig(templateName).getVcTemplate();
//        if (vcTemplateString == null) {
//            log.error("Template {} not found (vcTemplate is null)", templateName);
//            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND);
//        }
//
//        vcTemplateString = new String(Base64.decodeBase64(vcTemplateString));
        String vcTemplateString = "{\"nameSpaces\": {\"org.iso.18013.5.1\": [{\"digestID\": 0,\"elementIdentifier\": \"family_name\",\"elementValue\": \"${family_name}\"},{\"digestID\": 1,\"elementIdentifier\": \"given_name\", \"elementValue\": \"${given_name}\"},{\"digestID\": 2,\"elementIdentifier\": \"birth_date\",\"elementValue\": \"${birth_date}\"},{\"digestID\": 7,\"elementIdentifier\": \"driving_privileges\",\"elementValue\": ${driving_privileges}}]},\"docType\": \"${_docType}\",\"validityInfo\": {\"validFrom\": \"${_validFrom}\",\"validUntil\": \"${_validUntil}\"}}";

        StringWriter writer = new StringWriter();

        // Prepare template data for mDOC structure
        Map<String, Object> finalTemplate = jsonifyForMDoc(templateSettings);

        // Add Velocity tools
        finalTemplate.put("_dateTool", new DateTool());
        finalTemplate.put("_esc", new EscapeTool());
        finalTemplate.put("_issuer", issuer);

        // Add mDOC-specific metadata
        addMDocMetadata(finalTemplate, finalTemplate);

        if (!finalTemplate.containsKey("_validFrom")) {
            String validFrom = ZonedDateTime.now(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            finalTemplate.put("_validFrom", validFrom);
        }

        // Handle validUntil
        if (!finalTemplate.containsKey("_validUntil") && StringUtils.isNotEmpty(defaultExpiryDuration)) {
            Duration duration;
            try {
                duration = Duration.parse(defaultExpiryDuration);
            } catch (DateTimeParseException e) {
                // Default to 730 days (~2 years)
                duration = Duration.parse("P730D");
            }
            String validUntil = ZonedDateTime.now(ZoneOffset.UTC)
                    .plusSeconds(duration.getSeconds())
                    .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            finalTemplate.put("_validUntil", validUntil);
        }

        VelocityContext context = new VelocityContext(finalTemplate);
        engine.evaluate(context, writer, templateName, vcTemplateString);

        String result = writer.toString();

        // Post-process the mDOC structure to ensure proper formatting
        return postProcessMDocStructure(result);
    }

    @SneakyThrows
    @Override
    public String format(Map<String, Object> templateInput) {
        String templateName = templateInput.get(TEMPLATE_NAME).toString();
        String issuer = templateInput.get(ISSUER_URI).toString();

//        String vcTemplateString = getCachedCredentialConfig(templateName).getVcTemplate();
//        if (vcTemplateString == null) {
//            log.error("Template {} not found (vcTemplate is null)", templateName);
//            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND);
//        }
//
//        vcTemplateString = new String(Base64.decodeBase64(vcTemplateString));
        String vcTemplateString = "{\"nameSpaces\": {\"org.iso.18013.5.1\": [{\"digestID\": 0,\"elementIdentifier\": \"family_name\",\"elementValue\": \"${family_name}\"},{\"digestID\": 1,\"elementIdentifier\": \"given_name\", \"elementValue\": \"${given_name}\"},{\"digestID\": 2,\"elementIdentifier\": \"birth_date\",\"elementValue\": \"${birth_date}\"},{\"digestID\": 7,\"elementIdentifier\": \"driving_privileges\",\"elementValue\": ${driving_privileges}}]},\"docType\": \"${_docType}\",\"validityInfo\": {\"validFrom\": \"${_validFrom}\",\"validUntil\": \"${_validUntil}\"}}";

        StringWriter writer = new StringWriter();

        // Prepare template data for mDOC structure
        Map<String, Object> finalTemplate = jsonifyForMDoc(templateInput);

        // Add Velocity tools
        finalTemplate.put("_dateTool", new DateTool());
        finalTemplate.put("_esc", new EscapeTool());
        finalTemplate.put("_issuer", issuer);

        // Add mDOC-specific metadata
        addMDocMetadata(finalTemplate, finalTemplate);

        if (!finalTemplate.containsKey("_validFrom")) {
            String validFrom = ZonedDateTime.now(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            finalTemplate.put("_validFrom", validFrom);
        }

        // Handle validUntil
        if (!finalTemplate.containsKey("_validUntil") && StringUtils.isNotEmpty(defaultExpiryDuration)) {
            Duration duration;
            try {
                duration = Duration.parse(defaultExpiryDuration);
            } catch (DateTimeParseException e) {
                // Default to 730 days (~2 years)
                duration = Duration.parse("P730D");
            }
            String validUntil = ZonedDateTime.now(ZoneOffset.UTC)
                    .plusSeconds(duration.getSeconds())
                    .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            finalTemplate.put("_validUntil", validUntil);
        }

        VelocityContext context = new VelocityContext(finalTemplate);
        engine.evaluate(context, writer, templateName, vcTemplateString);

        String result = writer.toString();

        // Post-process the mDOC structure to ensure proper formatting
        return postProcessMDocStructure(result);
    }

    /**
     * Adds mDOC-specific metadata to the template data.
     */
    private void addMDocMetadata(Map<String, Object> finalTemplate, Map<String, Object> templateSettings) {
        // Add rendering template digest if needed
        if (templateSettings.containsKey(Constants.RENDERING_TEMPLATE_ID)) {
            try {
                finalTemplate.put("_renderMethodSVGdigest",
                        CredentialUtils.getDigestMultibase(renderingTemplateService.getTemplate(
                                (String) templateSettings.get(Constants.RENDERING_TEMPLATE_ID)).getTemplate()));
            } catch (RenderingTemplateException e) {
                log.error("SVG Template: {} not available in DB", templateSettings.get(Constants.RENDERING_TEMPLATE_ID), e);
            }
        }
    }

    /**
     * Post-processes the mDOC structure to ensure proper formatting.
     */
    private String postProcessMDocStructure(String result) {
        try {
            JSONObject mDocJson = new JSONObject(result);

            // Check for required mDOC fields
            if (!mDocJson.has("nameSpaces")) {
                log.warn("mDOC structure missing 'nameSpaces' field");
            }

            if (!mDocJson.has("docType")) {
                log.warn("mDOC structure missing 'docType' field");
            }

            // Validate nameSpaces structure
            if (mDocJson.has("nameSpaces")) {
                JSONObject nameSpaces = mDocJson.getJSONObject("nameSpaces");
                for (String namespace : nameSpaces.keySet()) {
                    Object namespaceValue = nameSpaces.get(namespace);
                    if (!(namespaceValue instanceof JSONArray)) {
                        log.warn("Namespace '{}' should contain an array of elements", namespace);
                    }
                }
            }

            // Add UUID if idPrefix is configured
            if (StringUtils.isNotEmpty(idPrefix)) {
                mDocJson.put("id", idPrefix + UUID.randomUUID());
            }

            return mDocJson.toString();
        } catch (Exception e) {
            log.error("Error post-processing mDOC structure", e);
            return result; // Return original if post-processing fails
        }
    }

    /**
     * Prepares data for mDOC CBOR encoding by ensuring proper data types.
     * This is similar to jsonify but with mDOC-specific considerations.
     */
    protected static Map<String, Object> jsonifyForMDoc(Map<String, Object> valueMap) {
        Map<String, Object> finalTemplate = new HashMap<>();

        for (Map.Entry<String, Object> entry : valueMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (value instanceof List) {
                finalTemplate.put(key, new JSONArray((List<Object>) value));
            } else if (value != null && value.getClass().isArray()) {
                finalTemplate.put(key, new JSONArray(Arrays.asList((Object[]) value)));
            } else if (value instanceof Integer || value instanceof Float ||
                    value instanceof Long || value instanceof Double) {
                // Numeric values don't need quoting
                finalTemplate.put(key, value);
            } else if (value instanceof Boolean) {
                // Boolean values for mDOC
                finalTemplate.put(key, value);
            } else if (value instanceof String) {
                // String values - DON'T use JSONObject.quote here as it adds extra quotes
                finalTemplate.put(key, value.toString());
            } else if (value instanceof Map) {
                // For nested maps, convert to JSONObject but don't quote
                finalTemplate.put(key, new JSONObject((Map<String, Object>) value));
            } else if (value != null) {
                // Other non-null types as string
                finalTemplate.put(key, value.toString());
            } else {
                // Handle null values
                finalTemplate.put(key, null);
            }
        }

        return finalTemplate;
    }
}