package io.mosip.certify.entity;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TemplateIdTest {

    @Test
    void testGettersAndSetters() {
        TemplateId templateId = new TemplateId();

        templateId.setContext("test-context");
        templateId.setCredentialType("test-type");

        assertEquals("test-context", templateId.getContext());
        assertEquals("test-type", templateId.getCredentialType());
    }

    @Test
    void testEqualsAndHashCode() {
        TemplateId id1 = new TemplateId();
        id1.setContext("context1");
        id1.setCredentialType("type1");

        TemplateId id2 = new TemplateId();
        id2.setContext("context1");
        id2.setCredentialType("type1");

        // Test reflexivity
        assertTrue(id1.equals(id1));

        // Test symmetry
        assertTrue(id1.equals(id2));
        assertTrue(id2.equals(id1));

        // Test hashCode
        assertEquals(id1.hashCode(), id2.hashCode());

        // Test null comparison
        assertFalse(id1.equals(null));

        // Test different type comparison
        assertFalse(id1.equals(new Object()));
    }

    @Test
    void testEqualsWithDifferentValues() {
        TemplateId base = new TemplateId();
        base.setContext("context");
        base.setCredentialType("type");

        // Test different context
        TemplateId diffContext = new TemplateId();
        diffContext.setContext("different-context");
        diffContext.setCredentialType("type");
        assertFalse(base.equals(diffContext));

        // Test different credential type
        TemplateId diffType = new TemplateId();
        diffType.setContext("context");
        diffType.setCredentialType("different-type");
        assertFalse(base.equals(diffType));

        // Test both fields different
        TemplateId bothDiff = new TemplateId();
        bothDiff.setContext("different-context");
        bothDiff.setCredentialType("different-type");
        assertFalse(base.equals(bothDiff));
    }

    @Test
    void testHashCodeConsistency() {
        TemplateId id = new TemplateId();
        id.setContext("context");
        id.setCredentialType("type");

        // Same values should produce same hash code
        int hash1 = id.hashCode();
        int hash2 = id.hashCode();
        assertEquals(hash1, hash2);

        // Different values should produce different hash codes
        TemplateId differentId = new TemplateId();
        differentId.setContext("different-context");
        differentId.setCredentialType("different-type");
        assertNotEquals(id.hashCode(), differentId.hashCode());
    }

    @Test
    void testNullFields() {
        TemplateId id1 = new TemplateId();
        TemplateId id2 = new TemplateId();

        // Both null fields should be equal
        assertTrue(id1.equals(id2));
        assertEquals(id1.hashCode(), id2.hashCode());

        // One null field
        id2.setContext("context");
        assertFalse(id1.equals(id2));

        // Both null in one field
        id1.setContext("context");
        id1.setCredentialType(null);
        id2.setCredentialType(null);
        assertTrue(id1.equals(id2));
        assertEquals(id1.hashCode(), id2.hashCode());
    }

    @Test
    void testConstructor() {
        // Test no-args constructor
        TemplateId templateId = new TemplateId();
        assertNull(templateId.getContext());
        assertNull(templateId.getCredentialType());

        // If you have an all-args constructor, test it too
        // Assuming you have one, uncomment and modify as needed:
        TemplateId templateId2 = new TemplateId("context", "type");
        assertEquals("context", templateId2.getContext());
        assertEquals("type", templateId2.getCredentialType());
    }
}