package io.mosip.certify.entity;

import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.time.LocalDateTime;
import static org.junit.jupiter.api.Assertions.*;

class RenderingTemplateTest {
    private Validator validator;
    private RenderingTemplate renderingTemplate;
    private final LocalDateTime testTime = LocalDateTime.now();

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();

        renderingTemplate = new RenderingTemplate();
        renderingTemplate.setId("test-id");
        renderingTemplate.setTemplate("Test Template");
        renderingTemplate.setCreatedtimes(testTime);
        renderingTemplate.setUpdatedtimes(testTime);
    }

    @Test
    void testValidRenderingTemplate() {
        var violations = validator.validate(renderingTemplate);
        assertTrue(violations.isEmpty());
    }

    @Test
    void testTemplateNotBlank() {
        // Test null template
        renderingTemplate.setTemplate(null);
        var violations = validator.validate(renderingTemplate);
        assertFalse(violations.isEmpty());
        assertEquals(ErrorConstants.EMPTY_TEMPLATE_CONTENT,
                violations.iterator().next().getMessage());

        // Test empty template
        renderingTemplate.setTemplate("");
        violations = validator.validate(renderingTemplate);
        assertFalse(violations.isEmpty());

        // Test blank template
        renderingTemplate.setTemplate("   ");
        violations = validator.validate(renderingTemplate);
        assertFalse(violations.isEmpty());
    }

    @Test
    void testEqualsAndHashCode() {
        // Create two identical templates
        RenderingTemplate template1 = new RenderingTemplate();
        template1.setId("test-id");
        template1.setTemplate("Test Template");
        template1.setCreatedtimes(testTime);
        template1.setUpdatedtimes(testTime);

        RenderingTemplate template2 = new RenderingTemplate();
        template2.setId("test-id");
        template2.setTemplate("Test Template");
        template2.setCreatedtimes(testTime);
        template2.setUpdatedtimes(testTime);

        // Test equals
        assertTrue(template1.equals(template1)); // Reflexivity
        assertTrue(template1.equals(template2)); // Equal objects
        assertTrue(template2.equals(template1)); // Symmetry
        assertFalse(template1.equals(null)); // Null check
        assertFalse(template1.equals(new Object())); // Different type

        // Test hashCode
        assertEquals(template1.hashCode(), template2.hashCode());
    }

    @Test
    void testEqualsWithDifferentFields() {
        RenderingTemplate base = createSampleTemplate();

        // Test different id
        RenderingTemplate diffId = createSampleTemplate();
        diffId.setId("different-id");
        assertFalse(base.equals(diffId));

        // Test different template
        RenderingTemplate diffTemplate = createSampleTemplate();
        diffTemplate.setTemplate("Different Template");
        assertFalse(base.equals(diffTemplate));

        // Test different created times
        RenderingTemplate diffCreatedTimes = createSampleTemplate();
        diffCreatedTimes.setCreatedtimes(testTime.plusDays(1));
        assertFalse(base.equals(diffCreatedTimes));

        // Test different updated times
        RenderingTemplate diffUpdatedTimes = createSampleTemplate();
        diffUpdatedTimes.setUpdatedtimes(testTime.plusDays(1));
        assertFalse(base.equals(diffUpdatedTimes));
    }

    @Test
    void testCanEqual() {
        RenderingTemplate template1 = new RenderingTemplate();
        RenderingTemplate template2 = new RenderingTemplate();
        Object otherObject = new Object();

        assertTrue(template1.canEqual(template2)); // Same class
        assertFalse(template1.canEqual(otherObject)); // Different class
    }

    @Test
    void testToString() {
        RenderingTemplate template = createSampleTemplate();
        String toString = template.toString();

        // Verify all fields are included
        assertTrue(toString.contains("test-id"));
        assertTrue(toString.contains("Test Template"));
        assertTrue(toString.contains(testTime.toString()));
    }

    @Test
    void testAllArgsConstructor() {
        String id = "test-id";
        String templateContent = "Test Template";
        LocalDateTime created = LocalDateTime.now();
        LocalDateTime updated = LocalDateTime.now();

        RenderingTemplate template = new RenderingTemplate(id, templateContent, created, updated);

        assertEquals(id, template.getId());
        assertEquals(templateContent, template.getTemplate());
        assertEquals(created, template.getCreatedtimes());
        assertEquals(updated, template.getUpdatedtimes());
    }

    private RenderingTemplate createSampleTemplate() {
        RenderingTemplate template = new RenderingTemplate();
        template.setId("test-id");
        template.setTemplate("Test Template");
        template.setCreatedtimes(testTime);
        template.setUpdatedtimes(testTime);
        return template;
    }
}