/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services.templating;

import java.io.StringWriter;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
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
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.certify.api.spi.VCFormatter;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCDMConstants;
import io.mosip.certify.core.exception.TemplateException;
import io.mosip.certify.core.repository.TemplateRepository;
import io.mosip.certify.core.spi.SvgTemplateService;
import io.mosip.certify.core.util.CommonUtil;
import io.mosip.certify.services.SVGRenderUtils;
import static io.mosip.certify.services.templating.VelocityTemplatingConstants.ISSUER_URI;
import static io.mosip.certify.services.templating.VelocityTemplatingConstants.SVG_TEMPLATE;
import static io.mosip.certify.services.templating.VelocityTemplatingConstants.TEMPLATE_NAME;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class VelocityTemplatingEngineImpl implements VCFormatter {
    VelocityEngine engine;
    public static final String DELIMITER = ":";
    Map<String, Map<String, String>> templateCache;
    @Autowired
    TemplateRepository templateRepository;
    @Autowired
    SvgTemplateService svgTemplateService;
    @Value("${mosip.certify.vcformat.vc.expiry:true}")
    boolean shouldHaveDates;
    @Value("${mosip.certify.issuer.id.field.prefix.url:}")
    String idPrefix;
    @Value("${mosip.certify.issuer.expiry:3650}") //This is in days
    int defaultExpiry;

    @PostConstruct
    public void initialize() {
        engine = new VelocityEngine();
        // TODO: The DataSourceResourceLoader can be used instead if there's a
        //  single primary key column and the table has a last modified date.
        templateCache = new HashMap<>();
        templateRepository.findAll().stream().forEach((template -> {
            Map<String, String> templateMap = new HashMap<>();
            ObjectMapper oMapper = new ObjectMapper();
            templateMap = oMapper.convertValue(template , Map.class);
            //BeanUtils.copyProperties(template, templateMap);
            templateCache.put(String.join(DELIMITER, template.getCredentialType(), template.getContext(),template.getCredentialFormat()), templateMap);
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
     * @param templateInput is the input from the DataProvider plugin
     * @param defaultSettings has some sensible defaults from Certify for
     *                        internal work such as locating the appropriate template
     * @return templated VC as a String
     */
    @SneakyThrows
    @Override
    public String format(JSONObject templateInput, Map<String, Object> defaultSettings) {
        // TODO: Isn't template name becoming too complex with VC_CONTEXTS & CREDENTIAL_TYPES both?
        String templateName = defaultSettings.get(TEMPLATE_NAME).toString();
        String issuer = defaultSettings.get(ISSUER_URI).toString();
        String t = templateCache.get(templateName).get("template");
        StringWriter writer = new StringWriter();
        
        defaultSettings.putAll(templateInput.toMap());
        Map<String, Object> finalTemplate = setupTemplateInput(defaultSettings);
        VelocityContext context = new VelocityContext(finalTemplate);
        engine.evaluate(context, writer, /*logTag */ templateName,t.toString());
        if (StringUtils.isNotEmpty(idPrefix)) {
            JSONObject j = new JSONObject(writer.toString());
            j.put(VCDMConstants.ID, idPrefix + UUID.randomUUID());
            return j.toString();
        }
        return writer.toString();
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
        String t = templateCache.get(templateName).get("template");   
        StringWriter writer = new StringWriter();

        Map<String, Object> finalTemplate = setupTemplateInput(templateInput);

        VelocityContext context = new VelocityContext(finalTemplate);
        boolean result = engine.evaluate(context, writer, /*logTag */ templateName,t.toString());
        if (result) {
            log.error("Error processing velocity template for {}", templateName);
        }
        // if (StringUtils.isNotEmpty(idPrefix)) {
        //     JSONObject j = new JSONObject(writer.toString());
        //     j.put(VCDMConstants.ID, idPrefix + UUID.randomUUID());
        //     return j.toString();
        // }
        return writer.toString();
    }


    private Map<String, Object> setupTemplateInput(Map<String, Object> input){
        String templateName = input.remove(TEMPLATE_NAME).toString();
        String issuer = input.remove(ISSUER_URI).toString();
       // String t = templateCache.get(templateName).get("template");
        String templateDigest = "";

        String validUntil = input.containsKey(VCDM2Constants.VALID_UNITL)?input.remove(VCDM2Constants.VALID_UNITL).toString(): ZonedDateTime.now(ZoneOffset.UTC).plusYears(2).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        String validFrom = input.containsKey(VCDM2Constants.VALID_FROM)?input.remove(VCDM2Constants.VALID_FROM).toString(): ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        String id = input.containsKey(VCDMConstants.ID) ? idPrefix + input.remove(VCDMConstants.ID): idPrefix + UUID.randomUUID();
        String randomID = idPrefix + UUID.randomUUID();
        long iat = Instant.now().getEpochSecond();
        long exp = Instant.now().plus(defaultExpiry, ChronoUnit.DAYS).getEpochSecond();
        
        if (input.containsKey(SVG_TEMPLATE) && templateName.contains(VCDM2Constants.URL)) {
            try {

                templateDigest = SVGRenderUtils.getDigestMultibase(svgTemplateService.getSvgTemplate(
                                 CommonUtil.generateType5UUID((String) input.remove(SVG_TEMPLATE))).getTemplate());

            } catch (TemplateException e) {
                log.error("SVG Template: " + input.get(SVG_TEMPLATE) + " not available in DB", e);
            }
        }

        Map<String, Object> finalTemplate = input;
        // Date: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/DateTool.html
        finalTemplate.put("_dateTool", new DateTool());
        // Escape: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/EscapeTool.html
        finalTemplate.put("_esc", new EscapeTool());
        // add the issuer value
        finalTemplate.put("_issuer", issuer);
        finalTemplate.put("_renderMethodSVGdigest", templateDigest);
        finalTemplate.put("_validFrom", validFrom);
        finalTemplate.put("_validUntil", validUntil);
        finalTemplate.put("_iat", iat);
        finalTemplate.put("_exp",exp);
        finalTemplate.put("_nbf",iat);
        finalTemplate.put(VCDMConstants.ID, id);
        finalTemplate.put("_uuid", randomID);
        return finalTemplate;
    }
}
