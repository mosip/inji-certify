package io.mosip.certify.services.templating;

import io.mosip.certify.api.spi.VCFormatter;
import io.mosip.certify.core.repository.TemplateRepository;
import jakarta.annotation.PostConstruct;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
public class VelocityTemplatingEngineImpl implements VCFormatter {
    VelocityEngine engine;
    public static final String DELIMITER = ":";
    Map<String, String> templateCache;
    @Autowired
    TemplateRepository templateRepository;
    // DATA to be fetched from DB

    @Autowired
    public void setTemplateRepository(TemplateRepository templateRepository) {
        this.templateRepository = templateRepository;
    }

    @PostConstruct
    public void initialize() {
        // TODO: Get the template as a String from the DB
        engine = new VelocityEngine();
        // DataSourceResourceLoader ds = new DataSourceResourceLoader();
        // TODO: The DataSourceResourceLoader can be used instead if there's a
        //  single primary key column and the table has a last modified date.
        templateCache = new HashMap<>();
        templateRepository.findAll().stream().forEach((template -> {
            templateCache.put(String.join(DELIMITER, template.getContext(), template.getCredentialType()), template.getTemplate());
        }));
        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        engine.init();
    }

    // TODO: Add a public method for updating the Velocity template cache

    /**
     * performs the templating
     * NOTE: the defaultSettings map should have the "templateName" key set to
     *  "${VC_CONTEXT1,VC_CONTENXT2,VC_CONTEXT3...}:${CREDENTIALTYPE1,CREDENTIALTYPE2,CREDENTIALTYPE3...}"
     *
     * @param templateInput is the input from the DataProvider plugin
     * @param defaultSettings has some sensible defaults from Certify for
     *                        internal work such as locating the appropriate template
     * @return templated VC as a String
     */
    @Override
    public String format(Map<String, Object> templateInput, Map<String, Object> defaultSettings) {
        String templateName = templateInput.get("templateName").toString();
        // TODO: right now any name will work
        String t = templateCache.get(templateName);
        StringWriter writer = new StringWriter();
        VelocityContext context = new VelocityContext(templateInput);
        // TODO: Check config for templateName.* fields and apply those configs as well
        InputStream is = new ByteArrayInputStream(t.toString().getBytes(StandardCharsets.UTF_8));
        // TODO: pass a Reader to engine.evaluate
        engine.evaluate(context, writer, /*logTag */ templateName,t.toString());
        return writer.toString();
    }
}
