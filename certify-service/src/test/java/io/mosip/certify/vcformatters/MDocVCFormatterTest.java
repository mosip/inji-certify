package io.mosip.certify.vcformatters;

import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class MDocVCFormatterTest {
    private MDocVCFormatter formatter;
    private JSONObject sampleData;
    private Map<String, Object> templateSettings;

    @BeforeEach
    void setUp() {
        formatter = new MDocVCFormatter();
        
        // Sample data with basic fields
        sampleData = new JSONObject();
        sampleData.put("family_name", "Doe");
        sampleData.put("given_name", "John");
        sampleData.put("birth_date", "1990-01-01");
        
        // Basic template settings
        templateSettings = new HashMap<>();
        templateSettings.put("issuer", "did:example:123");
    }

    @Test
    void testBasicVCGeneration() {
        String result = formatter.format(sampleData, templateSettings);
        
        // Basic structure validation
        assertNotNull(result);
        assertTrue(result.contains("VerifiableCredential"));
        assertTrue(result.contains("Iso180135_1_mDL"));
        assertTrue(result.contains("did:example:123"));
    }

    @Test
    void testEmptyData() {
        JSONObject emptyData = new JSONObject();
        String result = formatter.format(emptyData, templateSettings);
        
        assertNotNull(result);
        assertTrue(result.contains("VerifiableCredential"));
    }
} 