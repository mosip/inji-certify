package io.mosip.certify.core.templating;

import io.mosip.certify.core.repository.TemplateRepository;
import junit.framework.TestCase;
import lombok.SneakyThrows;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader;
import org.json.JSONArray;
import org.junit.Before;
import org.junit.Test;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class VelocityTemplatingEngineImplTest extends TestCase {
    private VelocityEngine engine;

    @Before
    public void setUp() {
        engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        engine.setProperty("classpath.resource.loader.class", ClasspathResourceLoader.class.getName());
        engine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, "org.apache.velocity.runtime.log.NullLogChute");
        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        engine.init();
    }

    @SneakyThrows
    @Test
    public void testTemplating() {
        // 1. setup template
        Template t = engine.getTemplate("MockCredential1.vm");
        assert t != null;
        VelocityContext c = new VelocityContext();
        StringWriter writer = new StringWriter();
        engine.evaluate(c, writer, "SchoolTemplateTest", t.toString());
        String out = writer.toString();
        Map<String, Object> ret = new HashMap<>();
        ret.put("vcVer", "VC-V1");
        ret.put("fullName", "Amit Developer");
        ret.put("gender", "female");
        ret.put("dateOfBirth", "01/01/2022");
        ret.put("email", "amit@fakemail.com");
        ret.put("UIN", "1234567890");
        ret.put("phone", "1234567890");
        // both of the below work
        ret.put("addressLine1", List.of("1", "Fake building", "Fake Area", "Fake City", "Near Fake Landmark"));
        // ret.put("addressLine1", new String[]{"1", "Fake building", "Fake Area", "Fake City", "Near Fake Landmark"});
        ret.put("province", "Fake Area");
        ret.put("region", "FakeRegion");
        ret.put("postalCode", "123");
        ret.put("face", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX///+/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD/aNpbtEAAAAASUVORK5CYII");
        Map<String, Object> finalTemplate = new HashMap<>();
        for (String key : ret.keySet()) {
            Object value = ret.get(key);
            if (value instanceof List) {
                finalTemplate.put(key, new JSONArray((List<String>) value));
            } else if (value.getClass().isArray()) {
                finalTemplate.put(key, new JSONArray(List.of(value)));
            } else if (value instanceof JSONArray) {
                finalTemplate.put(key, new JSONArray(value));
            } else {
                finalTemplate.put(key, value);
            }
        }
        VelocityContext context = new VelocityContext(finalTemplate);
        engine.evaluate(context, writer, /*logTag */ "MockTemplate test logTag", t.toString());
        InputStream is = new ByteArrayInputStream(t.toString().getBytes(StandardCharsets.UTF_8));
        t.merge(context, writer);
        assert writer.toString().contains("Fake building");
    }
}