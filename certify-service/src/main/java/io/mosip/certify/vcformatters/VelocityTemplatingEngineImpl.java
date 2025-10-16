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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
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
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCDMConstants;
import io.mosip.certify.core.spi.RenderingTemplateService;
import io.mosip.certify.services.CredentialUtils;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import static io.mosip.certify.core.constants.Constants.*;


@Slf4j
@Service
public class VelocityTemplatingEngineImpl implements VCFormatter {
    VelocityEngine engine;

    @Autowired
    CredentialConfigRepository credentialConfigRepository;
    @Autowired
    RenderingTemplateService renderingTemplateService;

    @Value("${mosip.certify.data-provider-plugin.vc-expiry-duration:P730d}")
    String defaultExpiryDuration;

    @Value("${mosip.certify.data-provider-plugin.id-field-prefix-uri:}")
    String idPrefix;

    @PostConstruct
    public void initialize() {
        engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        engine.init();
        log.info("VelocityTemplatingEngineImpl initialized. Using Spring Cache for CredentialConfig.");
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
            log.error("Invalid templateKey format for getCachedCredentialConfig: {}. Expected 3 parts.", templateKey);
            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "Template key format requires 3 parts: " + templateKey);
        } else if(parts.length == 2) {
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

        // TemplateId constructor order: context, credentialType, credentialFormat
//        TemplateId tid = new TemplateId(context, credentialType, credentialFormat);

        return credentialConfigRepository
                .findByCredentialFormatAndCredentialTypeAndContext(credentialFormat, credentialType, context)
                .orElseThrow(() -> {
                    log.error("CredentialConfig not found in DB for key: {}", templateKey);
                    return new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, "CredentialConfig not found for key: " + templateKey);
                });
    }


    /**
     * Gets the proof/signature algorithm for this template
     * @param templateName is the name of the template.
     * @return Signature Algorithm name. This can also be null
     */
    @Override
    public String getProofAlgorithm(String templateName){
        // return templateCache.get(templateName).get("signatureAlgo"); // OLD
        return getCachedCredentialConfig(templateName).getSignatureAlgo(); // NEW
    }

    /**
     * Get the URL of the public key for this template
     * @param templateName is the name of the template.
     * @return URL of the public key.
     */
    @Override
    public String getDidUrl(String templateName){
        // return templateCache.get(templateName).get("didUrl"); // OLD
        return getCachedCredentialConfig(templateName).getDidUrl(); // NEW
    }

    /**
     * Get the refid of the key stored in keymanager.
     * @param templateName is the name of the template.
     * @return refid for the keymanager.
     */
    @Override
    public String getRefID(String templateName){
        // return templateCache.get(templateName).get("keyManagerRefId"); // OLD
        return getCachedCredentialConfig(templateName).getKeyManagerRefId(); // NEW
    }

    /**
     * Get the appid of the key stored in keymanager
     * @param templateName is the name of the template.
     * @return appid of the keymanager.
     */
    @Override
    public String getAppID(String templateName){

        return getCachedCredentialConfig(templateName).getKeyManagerAppId(); // NEW
    }

    /**
     * Gets the selective disclosure information.
     * @param templateName is the name of the template
     * @return the list of selective disclosure paths. In case of null
     * it returns an empty list.
     */
    @Override
    public List<String> getSelectiveDisclosureInfo(String templateName){
        String sdClaimValue = getCachedCredentialConfig(templateName).getSdClaim(); // NEW
        return Optional.ofNullable(sdClaimValue)
                .map(sd -> Arrays.asList(sd.split(",")))
                .orElseGet(ArrayList::new);
    }

    /**
     * Gets the crypto suite used for VC signature or proof generation
     * @param templateName is the name of the template
     * @return the crypto suite used for VC signature or proof generation
     */
    @Override
    public String getSignatureCryptoSuite(String templateName) {
        return getCachedCredentialConfig(templateName).getSignatureCryptoSuite(); // NEW
    }

    @Override
    public List<String> getCredentialStatusPurpose(String templateName) {
        return getCachedCredentialConfig(templateName).getCredentialStatusPurposes();
    }

    /**
     * performs the templating
     * NOTE: the defaultSettings map should have the "templateName" key set to
     *  "${sort(CREDENTIALTYPE1,CREDENTIALTYPE2,CREDENTIALTYPE3...)}:${sort(VC_CONTEXT1,VC_CONTENXT2,VC_CONTEXT3...)}"
     *
     * @param valueMap is the input from the DataProvider plugin
     * @param templateSettings has some sensible defaults from Certify for
     *                        internal work such as locating the appropriate template
     * @return templated VC as a String
     */
    @SneakyThrows
    @Override
    public String format(JSONObject valueMap, Map<String, Object> templateSettings) {
        String templateName = templateSettings.get(TEMPLATE_NAME).toString();
        String issuer = templateSettings.get(DID_URL).toString();
        String vcTemplateString = getCachedCredentialConfig(templateName).getVcTemplate(); // NEW
        if (vcTemplateString == null) {
            log.error("Template {} not found (vcTemplate is null)", templateName);
            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND);
        }
        vcTemplateString = new String(Base64.decodeBase64(vcTemplateString));
        StringWriter writer = new StringWriter();
        Map<String, Object> finalTemplate = jsonify(valueMap.toMap());
        // Date: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/DateTool.html
        finalTemplate.put("_dateTool", new DateTool());
        // Escape: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/EscapeTool.html
        finalTemplate.put("_esc", new EscapeTool());
        // add the issuer value
        finalTemplate.put("_issuer", issuer);
        if (templateSettings.containsKey(Constants.RENDERING_TEMPLATE_ID) && templateName.contains(VCDM2Constants.URL)) {
            try {
                finalTemplate.put("_renderMethodSVGdigest",
                        CredentialUtils.getDigestMultibase(renderingTemplateService.getTemplate(
                                (String) templateSettings.get(Constants.RENDERING_TEMPLATE_ID)).getTemplate()));
            } catch (RenderingTemplateException e) {
                log.error("SVG Template: " + templateSettings.get(Constants.RENDERING_TEMPLATE_ID) + " not available in DB", e);
            }
        }
        if (!valueMap.has(VCDM2Constants.VALID_UNTIL) && StringUtils.isNotEmpty(defaultExpiryDuration)) {
            Duration duration;
            try {
                duration = Duration.parse(defaultExpiryDuration);
            } catch (DateTimeParseException e) {
                // set 730days(~2Y) as default VC expiry
                duration = Duration.parse("P730D");
            }
            String expiryTime = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(duration.getSeconds()).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            finalTemplate.put(VCDM2Constants.VALID_UNTIL, expiryTime);
        }
        if (!valueMap.has(VCDM2Constants.VALID_FROM)) {
            finalTemplate.put(VCDM2Constants.VALID_FROM, ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN)));
        }
        VelocityContext context = new VelocityContext(finalTemplate);
        engine.evaluate(context, writer, /*logTag */ templateName, vcTemplateString);
        if (StringUtils.isNotEmpty(idPrefix)) {
            JSONObject j = new JSONObject(writer.toString());
            j.put(VCDMConstants.ID, idPrefix + UUID.randomUUID());
            return j.toString();
        }
        return writer.toString();
    }

    /**
     * jsonify wraps a complex object into it's JSON representation
     * @param valueMap
     * @return
     */
    protected static Map<String, Object> jsonify(Map<String, Object> valueMap) {
        Map<String, Object> finalTemplate = new HashMap<>();
        Iterator<String> keys = valueMap.keySet().iterator();
        while(keys.hasNext()) {
            String key = keys.next();
            Object value = valueMap.get(key);
            if (value instanceof List) {
                finalTemplate.put(key, new JSONArray((List<Object>) value));
            } else if (value.getClass().isArray()) {
                finalTemplate.put(key, new JSONArray(List.of(value)));
            } else if (value instanceof Integer | value instanceof Float | value instanceof Long | value instanceof Double) {
                // entities which don't need to be quoted
                finalTemplate.put(key, value);
            } else if (value instanceof String){
                // entities which need to be quoted
                finalTemplate.put(key, JSONObject.wrap(value));
            } else if( value instanceof Map<?,?>) {
                finalTemplate.put(key,JSONObject.wrap(value));
            }
            else {
                // no conversion needed
                finalTemplate.put(key, value);
            }
        }
        return finalTemplate;
    }

    /**
     * performs the templating
     * NOTE: the defaultSettings map should have the "templateName" key set to
     *  "${sort(CREDENTIALTYPE1,CREDENTIALTYPE2,CREDENTIALTYPE3...)}:${sort(VC_CONTEXT1,VC_CONTENXT2,VC_CONTEXT3...)}"
     *
     * @param templateInput is the merged input from the DataProvider plugin and all the default settings as one single map
     * @return templated VC as a String
     */
    @SneakyThrows
    @Override
    public String format(Map<String, Object> templateInput) {
        // TODO: Isn't template name becoming too complex with VC_CONTEXTS & CREDENTIAL_TYPES both?
        String templateName = templateInput.get(TEMPLATE_NAME).toString();
        String issuer = templateInput.get(DID_URL).toString();
        String vcTemplateString = getCachedCredentialConfig(templateName).getVcTemplate(); // NEW
        vcTemplateString = new String(Base64.decodeBase64(vcTemplateString));
        StringWriter writer = new StringWriter();
        // 1. Prepare map
        Map<String, Object> finalTemplate = jsonify(templateInput);
        // TODO: Eventually, the credentialSubject from the plugin will be templated as-is
        // Date: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/DateTool.html
        finalTemplate.put("_dateTool", new DateTool());
        // Escape: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/EscapeTool.html
        finalTemplate.put("_esc", new EscapeTool());
        // add the issuer value
        finalTemplate.put("_issuer", issuer);
        if (templateInput.containsKey(Constants.RENDERING_TEMPLATE_ID) && templateName.contains(VCDM2Constants.URL)) {
            try {
                finalTemplate.put("_renderMethodSVGdigest",
                        CredentialUtils.getDigestMultibase(renderingTemplateService.getTemplate(
                                (String) templateInput.get(Constants.RENDERING_TEMPLATE_ID)).getTemplate()));
            } catch (RenderingTemplateException e) {
                log.error("Template: " + templateInput.get(Constants.RENDERING_TEMPLATE_ID) + " not available in DB", e);
            }
        }
        VelocityContext context = new VelocityContext(finalTemplate);
        engine.evaluate(context, writer, /*logTag */ templateName, vcTemplateString); // use vcTemplateString
        JSONObject jsonObject = new JSONObject(writer.toString());
        if (templateInput.containsKey(VCDMConstants.CREDENTIAL_ID)) {
            jsonObject.put(VCDMConstants.ID, templateInput.get(VCDMConstants.CREDENTIAL_ID));
        }
        if(templateInput.containsKey(VCDM2Constants.CREDENTIAL_STATUS) && templateName.contains(VCDM2Constants.URL)) {
            jsonObject.put(VCDM2Constants.CREDENTIAL_STATUS, templateInput.get(VCDM2Constants.CREDENTIAL_STATUS));
        }
        if( templateInput.containsKey(VCTYPE) && templateInput.containsKey(CONFIRMATION)
                && templateInput.containsKey(ISSUER)) {
            jsonObject.put(VCTYPE, templateInput.get(VCTYPE));
            jsonObject.put(CONFIRMATION, templateInput.get(CONFIRMATION));
            jsonObject.put(ISSUER, templateInput.get(ISSUER));
        }

        return jsonObject.toString();
    }
}