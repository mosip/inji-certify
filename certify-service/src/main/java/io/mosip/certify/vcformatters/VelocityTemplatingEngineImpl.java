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

import com.fasterxml.jackson.databind.ObjectMapper;

import org.json.JSONArray;
import org.json.JSONObject;

import io.micrometer.tracing.SamplerFunction;
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
import static io.mosip.certify.core.constants.Constants.ISSUER_URI;
import static io.mosip.certify.core.constants.Constants.TEMPLATE_NAME;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;


import io.mosip.certify.credential.Credential;


@Slf4j
@Service
public class VelocityTemplatingEngineImpl implements VCFormatter {
    VelocityEngine engine;
    public static final String DELIMITER = ":";
    Map<String, Map<String, String>> templateCache;
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
        // TODO: The DataSourceResourceLoader can be used instead if there's a
        //  single primary key column and the table has a last modified date.
        templateCache = new HashMap<>();
        credentialConfigRepository.findAll().stream().forEach((template -> {
            Map<String, String> templateMap = new HashMap<>();
            ObjectMapper oMapper = new ObjectMapper();
            templateMap = oMapper.convertValue(template , Map.class);
            //BeanUtils.copyProperties(template, templateMap);
            templateCache.put(String.join(DELIMITER, template.getCredentialType(), template.getContext(), template.getCredentialFormat()), templateMap);
         }));
        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        engine.init();
    }

    // TODO: Add a public method for updating the Velocity template cache


    /**
     * Gets the proof/signature algorithm for this template
     * @param templateName is the name of the template.
     * @return Signature Algorithm name. This can also be null
     */
    @Override
    public String getProofAlgorithm(String templateName){
        return templateCache.get(templateName).get("signatureAlgo");
    }

    /**
     * Get the URL of the public key for this template
     * @param templateName is the name of the template.
     * @return URL of the public key.
     */
    @Override
    public String getDidUrl(String templateName){
        return templateCache.get(templateName).get("didUrl");
    }

    /**
     * Get the refid of the key stored in keymanager.
     * @param templateName is the name of the template.
     * @return refid for the keymanager.
     */
    @Override
    public String getRefID(String templateName){
        return templateCache.get(templateName).get("keyManagerRefId");
    }

    /**
     * Get the appid of the key stored in keymanager
     * @param templateName is the name of the template.
     * @return appid of the keymanager.
     */
    @Override
    public String getAppID(String templateName){
        return templateCache.get(templateName).get("keyManagerAppId");
    }

    /**
     * Gets the selective disclosure information.
     * @param templateName is the name of the template
     * @return the list of selective disclosure paths. In case of null
     * it returns an empty list.
     */
    @Override
    public List<String> getSelectiveDisclosureInfo(String templateName){

        return Optional.ofNullable(templateCache.get(templateName).get("sdClaim"))
                          .map(sd -> Arrays.asList(sd.split(",")))
                          .orElse(new ArrayList<>());
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
        // TODO: Isn't template name becoming too complex with VC_CONTEXTS & CREDENTIAL_TYPES both?
        String templateName = templateSettings.get(TEMPLATE_NAME).toString();
        String issuer = templateSettings.get(ISSUER_URI).toString();
        String template = templateCache.get(templateName).get("vcTemplate");

        if (template == null) {
            log.error("Template {} not found", templateName);
            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND);
        }
        StringWriter writer = new StringWriter();
        // 1. Prepare map
        // TODO: Eventually, the credentialSubject from the plugin will be templated as-is
        Map<String, Object> finalTemplate = new HashMap<>();
        Iterator<String> keys = valueMap.keys();
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
            } else {
                //no conversion needed
                finalTemplate.put(key, value);
            }
        }
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
        if (!valueMap.has(VCDM2Constants.VALID_UNITL) && StringUtils.isNotEmpty(defaultExpiryDuration)) {
            Duration duration;
            try {
                duration = Duration.parse(defaultExpiryDuration);
            } catch (DateTimeParseException e) {
                // set 730days(~2Y) as default VC expiry
                duration = Duration.parse("P730D");
            }
            String expiryTime = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(duration.getSeconds()).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            finalTemplate.put(VCDM2Constants.VALID_UNITL, expiryTime);
        }
        if (!valueMap.has(VCDM2Constants.VALID_FROM)) {
            finalTemplate.put(VCDM2Constants.VALID_FROM, ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN)));
        }
        VelocityContext context = new VelocityContext(finalTemplate);
        engine.evaluate(context, writer, /*logTag */ templateName,template.toString());
        if (StringUtils.isNotEmpty(idPrefix)) {
            JSONObject j = new JSONObject(writer.toString());
            j.put(VCDMConstants.ID, idPrefix + UUID.randomUUID());
            return j.toString();
        }
        return writer.toString();
    }

    /**
     * getTemplate fetches the VelocityTemplate from the DB or Spring Cache
     * @param key key is a combination of sorted credentialType & sorted
     *            context separated by a ':'.
     * @return
     */
    @Cacheable(cacheNames = "template", key = "#key")
    public String getTemplate(String key) {
        if (!key.contains(DELIMITER)) {
            return null;
        }
        String credentialType = key.split(DELIMITER)[0];
        String context = key.split(DELIMITER, 2)[1];
        CredentialConfig template = credentialConfigRepository.findByCredentialTypeAndContext(credentialType, context).orElse(null);
        if (template != null) {
            return template.getVcTemplate();
        } else
            return null;
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
        String issuer = templateInput.get(ISSUER_URI).toString();
        String t = templateCache.get(templateName).get("vcTemplate");
        StringWriter writer = new StringWriter();
        // 1. Prepare map
        // TODO: Eventually, the credentialSubject from the plugin will be templated as-is
        Map<String, Object> finalTemplate = templateInput;
        // Date: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/DateTool.html
        finalTemplate.put("_dateTool", new DateTool());
        // Escape: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/EscapeTool.html
        finalTemplate.put("_esc", new EscapeTool());
        // add the issuer value
        finalTemplate.put("_issuer", issuer);
        if (templateInput.containsKey(Constants.TEMPLATE_NAME) && templateName.contains(VCDM2Constants.URL)) {
            try {
                finalTemplate.put("_renderMethodSVGdigest",
                        CredentialUtils.getDigestMultibase(renderingTemplateService.getTemplate(
                                (String) templateInput.get(Constants.TEMPLATE_NAME)).getTemplate()));
            } catch (RenderingTemplateException e) {
                log.error("Template: " + templateInput.get(Constants.TEMPLATE_NAME) + " not available in DB", e);
            }
        }
        if (!(templateInput.containsKey(VCDM2Constants.VALID_FROM)
                && templateInput.containsKey(VCDM2Constants.VALID_UNITL))) {
            String time = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            // hardcoded time
            String expiryTime = ZonedDateTime.now(ZoneOffset.UTC).plusYears(2).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            finalTemplate.put(VCDM2Constants.VALID_FROM, time);
            finalTemplate.put(VCDM2Constants.VALID_UNITL, expiryTime);
        }
        VelocityContext context = new VelocityContext(finalTemplate);
        engine.evaluate(context, writer, /*logTag */ templateName,t.toString());
        if (StringUtils.isNotEmpty(idPrefix)) {
            JSONObject j = new JSONObject(writer.toString());
            j.put(VCDMConstants.ID, idPrefix + UUID.randomUUID());
            return j.toString();
        }
        return writer.toString();
    }
}
