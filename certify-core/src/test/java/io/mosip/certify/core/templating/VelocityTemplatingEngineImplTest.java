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
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class VelocityTemplatingEngineImplTest extends TestCase {
    private VelocityEngine engine;
    private final Map<String, Template> templateCache = new ConcurrentHashMap<>();
    @MockBean
    private TemplateRepository templateRepository;

    @Before
    public void setUp() throws Exception {
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
        Template t = engine.getTemplate("MockCredential.vm");
        assert t != null;
        VelocityContext c = new VelocityContext();
        StringWriter writer = new StringWriter();
        engine.evaluate(c, writer, "SchoolTemplateTest", t.toString());
        String out = writer.toString();
        Map<String, Object> res = new RestTemplate().getForObject(
                "https://api.dev1.mosip.net/v1/mock-identity-system/identity/34455445765",
                HashMap.class);
        res = (Map<String, Object>) res.get("response");
        Map<String, Object> ret = new HashMap<>();
        ret.put("vcVer", "VC-V1");
        ret.put("name", res.get("name"));
        ret.put("fullName", res.get("fullName"));
        ret.put("gender", res.get("gender"));
        ret.put("dateOfBirth", res.get("dateOfBirth"));
        ret.put("email", res.get("email"));
        ret.put("UIN", "34455445765");
        ret.put("phone", res.get("phone"));
        ret.put("addressLine1", res.get("streetAddress"));
        ret.put("province", res.get("locality"));
        ret.put("region", res.get("region"));
        ret.put("postalCode", res.get("postalCode"));
        ret.put("face", res.get("encodedPhoto"));
        Map<String, Object> finalTemplate = new HashMap<>();
        for (String key : ret.keySet()) {
            Object value = ret.get(key);
            if (value instanceof List) {
                finalTemplate.put(key, new JSONArray((List<String>) value));
            } else if (value instanceof JSONArray) {
                finalTemplate.put(key, new JSONArray(value));
            } else {
                finalTemplate.put(key, value);
            }
        }
        VelocityContext context = new VelocityContext(finalTemplate);
        InputStream is = new ByteArrayInputStream(t.toString().getBytes(StandardCharsets.UTF_8));
        t.merge(context, writer);
    }
}