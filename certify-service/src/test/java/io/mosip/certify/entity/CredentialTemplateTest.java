package io.mosip.certify.entity;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.time.LocalDateTime;
import static org.junit.jupiter.api.Assertions.*;

class CredentialTemplateTest {
    private Validator validator;
    private CredentialTemplate credentialTemplate;
    private final LocalDateTime testTime = LocalDateTime.now();

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();

        credentialTemplate = new CredentialTemplate();
        credentialTemplate.setTemplate("Test Template");
        credentialTemplate.setContext("Test Context");
        credentialTemplate.setCredentialType("Test Type");
        credentialTemplate.setCreatedTimes(testTime);
        credentialTemplate.setUpdatedTimes(testTime);
    }

    @Test
    void testValidCredentialTemplate() {
        var violations = validator.validate(credentialTemplate);
        assertTrue(violations.isEmpty());
    }

    @Test
    void testTemplateNotBlank() {
        // Test null template
        credentialTemplate.setTemplate(null);
        var violations = validator.validate(credentialTemplate);
        assertFalse(violations.isEmpty());
        assertEquals("Template is mandatory",
                violations.iterator().next().getMessage());

        // Test empty template
        credentialTemplate.setTemplate("");
        violations = validator.validate(credentialTemplate);
        assertFalse(violations.isEmpty());
        assertEquals("Template is mandatory",
                violations.iterator().next().getMessage());

        // Test blank template
        credentialTemplate.setTemplate("   ");
        violations = validator.validate(credentialTemplate);
        assertFalse(violations.isEmpty());
        assertEquals("Template is mandatory",
                violations.iterator().next().getMessage());
    }

    @Test
    void testContextId() {
        String testContext = "Test Context";
        credentialTemplate.setContext(testContext);
        assertEquals(testContext, credentialTemplate.getContext());

        // Test null context
        credentialTemplate.setContext(null);
        assertNull(credentialTemplate.getContext());
    }

    @Test
    void testCredentialType() {
        String testType = "Test Type";
        credentialTemplate.setCredentialType(testType);
        assertEquals(testType, credentialTemplate.getCredentialType());

        // Test null credential type
        credentialTemplate.setCredentialType(null);
        assertNull(credentialTemplate.getCredentialType());
    }

    @Test
    void testCreatedTimes() {
        // Test NotNull constraint
        credentialTemplate.setCreatedTimes(null);
        var violations = validator.validate(credentialTemplate);
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("createdTimes")));

        // Test valid created times
        LocalDateTime testDateTime = LocalDateTime.now();
        credentialTemplate.setCreatedTimes(testDateTime);
        assertEquals(testDateTime, credentialTemplate.getCreatedTimes());
    }

    @Test
    void testUpdatedTimes() {
        // Test that updated times can be null
        credentialTemplate.setUpdatedTimes(null);
        var violations = validator.validate(credentialTemplate);
        assertTrue(violations.isEmpty());

        // Test setting and getting updated times
        LocalDateTime testDateTime = LocalDateTime.now();
        credentialTemplate.setUpdatedTimes(testDateTime);
        assertEquals(testDateTime, credentialTemplate.getUpdatedTimes());
    }

    @Test
    void testAllFieldsConstructionAndGetters() {
        String template = "Test Template";
        String context = "Test Context";
        String credentialType = "Test Type";
        LocalDateTime createdTime = LocalDateTime.now();
        LocalDateTime updatedTime = LocalDateTime.now();

        CredentialTemplate ct = new CredentialTemplate();
        ct.setTemplate(template);
        ct.setContext(context);
        ct.setCredentialType(credentialType);
        ct.setCreatedTimes(createdTime);
        ct.setUpdatedTimes(updatedTime);

        assertEquals(template, ct.getTemplate());
        assertEquals(context, ct.getContext());
        assertEquals(credentialType, ct.getCredentialType());
        assertEquals(createdTime, ct.getCreatedTimes());
        assertEquals(updatedTime, ct.getUpdatedTimes());
    }

    @Test
    void testEqualsAndHashCode() {
        // Create two identical credential templates
        CredentialTemplate ct1 = new CredentialTemplate();
        ct1.setTemplate("Test Template");
        ct1.setContext("Test Context");
        ct1.setCredentialType("Test Type");
        ct1.setCreatedTimes(LocalDateTime.now());
        ct1.setUpdatedTimes(LocalDateTime.now());

        CredentialTemplate ct2 = new CredentialTemplate();
        ct2.setTemplate("Test Template");
        ct2.setContext("Test Context");
        ct2.setCredentialType("Test Type");
        ct2.setCreatedTimes(ct1.getCreatedTimes());
        ct2.setUpdatedTimes(ct1.getUpdatedTimes());

        // Test equals
        assertTrue(ct1.equals(ct1)); // Same object
        assertTrue(ct1.equals(ct2)); // Equal objects
        assertTrue(ct2.equals(ct1)); // Symmetry
        assertFalse(ct1.equals(null)); // Null comparison
        assertFalse(ct1.equals(new Object())); // Different type

        // Test with different values
        CredentialTemplate ct3 = new CredentialTemplate();
        ct3.setTemplate("Different Template");
        ct3.setContext("Different Context");
        ct3.setCredentialType("Different Type");
        ct3.setCreatedTimes(LocalDateTime.now());
        ct3.setUpdatedTimes(LocalDateTime.now());

        assertFalse(ct1.equals(ct3));

        // Test hashCode
        assertEquals(ct1.hashCode(), ct2.hashCode()); // Equal objects should have equal hash codes
        assertNotEquals(ct1.hashCode(), ct3.hashCode()); // Different objects should have different hash codes
    }

    @Test
    void testCanEqual() {
        CredentialTemplate ct1 = new CredentialTemplate();
        CredentialTemplate ct2 = new CredentialTemplate();
        Object obj = new Object();

        assertTrue(ct1.canEqual(ct2)); // Same class
        assertFalse(ct1.canEqual(obj)); // Different class
    }

    @Test
    void testToString() {
        CredentialTemplate ct = new CredentialTemplate();
        ct.setTemplate("Test Template");
        ct.setContext("Test Context");
        ct.setCredentialType("Test Type");
        LocalDateTime testTime = LocalDateTime.now();
        ct.setCreatedTimes(testTime);
        ct.setUpdatedTimes(testTime);

        String toString = ct.toString();

        // Verify all fields are included in toString
        assertTrue(toString.contains("Test Template"));
        assertTrue(toString.contains("Test Context"));
        assertTrue(toString.contains("Test Type"));
        assertTrue(toString.contains(testTime.toString()));
    }

    @Test
    void testEqualsWithDifferentFields() {
        CredentialTemplate base = new CredentialTemplate();
        base.setTemplate("Template");
        base.setContext("Context");
        base.setCredentialType("Type");
        base.setCreatedTimes(LocalDateTime.now());
        base.setUpdatedTimes(LocalDateTime.now());

        // Test different template
        CredentialTemplate diffTemplate = new CredentialTemplate();
        diffTemplate.setTemplate("Different");
        diffTemplate.setContext(base.getContext());
        diffTemplate.setCredentialType(base.getCredentialType());
        diffTemplate.setCreatedTimes(base.getCreatedTimes());
        diffTemplate.setUpdatedTimes(base.getUpdatedTimes());
        assertFalse(base.equals(diffTemplate));

        // Test different context
        CredentialTemplate diffContext = new CredentialTemplate();
        diffContext.setTemplate(base.getTemplate());
        diffContext.setContext("Different");
        diffContext.setCredentialType(base.getCredentialType());
        diffContext.setCreatedTimes(base.getCreatedTimes());
        diffContext.setUpdatedTimes(base.getUpdatedTimes());
        assertFalse(base.equals(diffContext));

        // Test different credential type
        CredentialTemplate diffType = new CredentialTemplate();
        diffType.setTemplate(base.getTemplate());
        diffType.setContext(base.getContext());
        diffType.setCredentialType("Different");
        diffType.setCreatedTimes(base.getCreatedTimes());
        diffType.setUpdatedTimes(base.getUpdatedTimes());
        assertFalse(base.equals(diffType));

        // Test different created times
        CredentialTemplate diffCreatedTimes = new CredentialTemplate();
        diffCreatedTimes.setTemplate(base.getTemplate());
        diffCreatedTimes.setContext(base.getContext());
        diffCreatedTimes.setCredentialType(base.getCredentialType());
        diffCreatedTimes.setCreatedTimes(LocalDateTime.now().plusDays(1));
        diffCreatedTimes.setUpdatedTimes(base.getUpdatedTimes());
        assertFalse(base.equals(diffCreatedTimes));

        // Test different updated times
        CredentialTemplate diffUpdatedTimes = new CredentialTemplate();
        diffUpdatedTimes.setTemplate(base.getTemplate());
        diffUpdatedTimes.setContext(base.getContext());
        diffUpdatedTimes.setCredentialType(base.getCredentialType());
        diffUpdatedTimes.setCreatedTimes(base.getCreatedTimes());
        diffUpdatedTimes.setUpdatedTimes(LocalDateTime.now().plusDays(1));
        assertFalse(base.equals(diffUpdatedTimes));
    }
}