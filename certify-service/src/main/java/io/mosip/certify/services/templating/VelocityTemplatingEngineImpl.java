/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services.templating;

import java.io.*;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import io.mosip.certify.api.spi.VCFormatter;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.repository.TemplateRepository;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.tools.generic.DateTool;
import org.apache.velocity.tools.generic.EscapeTool;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class VelocityTemplatingEngineImpl implements VCFormatter {
    VelocityEngine engine;
    public static final String DELIMITER = ":";
    Map<String, String> templateCache;
    @Autowired
    TemplateRepository templateRepository;
    @Value("${mosip.certify.vcformat.vc.expiry:true}")
    boolean shouldHaveDates;

    @PostConstruct
    public void initialize() {
        engine = new VelocityEngine();
        // TODO: The DataSourceResourceLoader can be used instead if there's a
        //  single primary key column and the table has a last modified date.
        templateCache = new HashMap<>();
        templateRepository.findAll().stream().forEach((template -> templateCache.put(String.join(DELIMITER, template.getCredentialType(), template.getContext()), template.getTemplate())));
        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        engine.init();
    }

    // TODO: Add a public method for updating the Velocity template cache

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
    public String format(Map<String, Object> templateInput, Map<String, Object> defaultSettings) {
        // TODO: Isn't template name becoming too complex with VC_CONTEXTS & CREDENTIAL_TYPES both?
        String templateName = defaultSettings.get("templateName").toString();
        String issuer = defaultSettings.get("issuerURI").toString();
        String t = templateCache.get(templateName);
        StringWriter writer = new StringWriter();
        // 1. Prepare map
        // TODO: Eventually, the credentialSubject from the plugin will be templated as-is
        Map<String, Object> finalTemplate = new HashMap<>();
        for (String key : templateInput.keySet()) {
            Object value = templateInput.get(key);
            if (value instanceof List) {
                // TODO(problem area): handle field values with unescaped JSON
                //  reserved literals such as " or ,
                // (Q) Should Object always be a JSONObject?
                finalTemplate.put(key, new JSONArray((List<Object>) value));
            } else if (value.getClass().isArray()) {
                finalTemplate.put(key, new JSONArray(List.of(value)));
            } else if (value instanceof Integer | value instanceof Float | value instanceof Long | value instanceof Double) {
                // entities which don't need to be quoted
                finalTemplate.put(key, value);
            } else if (value instanceof String){
                // entities which need to be quoted
                finalTemplate.put(key, JSONObject.wrap(value));
            }
        }
        // Date: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/DateTool.html
        finalTemplate.put("_dateTool", new DateTool());
        // Escape: https://velocity.apache.org/tools/3.1/apidocs/org/apache/velocity/tools/generic/EscapeTool.html
        finalTemplate.put("_esc", new EscapeTool());
        // add the issuer value
        finalTemplate.put("issuer", issuer);
        if (shouldHaveDates && !(templateInput.containsKey(VCDM2Constants.VALID_FROM)
                && templateInput.containsKey(VCDM2Constants.VALID_UNITL))) {
            String time = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            // hardcoded time
            String expiryTime = ZonedDateTime.now(ZoneOffset.UTC).plusYears(2).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            finalTemplate.put(VCDM2Constants.VALID_FROM, time);
            finalTemplate.put(VCDM2Constants.VALID_UNITL, expiryTime);
        }
        VelocityContext context = new VelocityContext(finalTemplate);
        engine.evaluate(context, writer, /*logTag */ templateName,t.toString());
        return writer.toString();
    }
}
