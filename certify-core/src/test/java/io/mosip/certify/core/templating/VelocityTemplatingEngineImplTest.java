package io.mosip.certify.core.templating;

import junit.framework.TestCase;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader;
import org.junit.Before;
import org.junit.Test;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class VelocityTemplatingEngineImplTest extends TestCase {
    private VelocityEngine engine;
    private final Map<String, Template> templateCache = new ConcurrentHashMap<>();

    @Before
    public void setUp() throws Exception {
        engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        engine.setProperty("classpath.resource.loader.class", ClasspathResourceLoader.class.getName());
        engine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, "org.apache.velocity.runtime.log.NullLogChute");
        engine.init();
    }

    @Test
    public void testTemplating() {
        // 1. setup template
        Template t = engine.getTemplate("SchoolTemplate.vm");
        assert t != null;
        Map<String, Object> templateInput = new HashMap<>();
        VelocityContext c = new VelocityContext();
        StringWriter writer = new StringWriter();
        engine.evaluate(c, writer, "SchoolTemplateTest", t.toString());
        String out = writer.toString();

    }
}