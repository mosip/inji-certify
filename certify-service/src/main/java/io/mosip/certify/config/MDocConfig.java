package io.mosip.certify.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "mosip.certify.mdoc")
public class MDocConfig {

    /**
     * Default digest algorithm for MSO (e.g., "SHA-256")
     */
    private String digestAlgorithm = "SHA-256";

    /**
     * MSO version string
     */
    private String msoVersion = "1.0";

    /**
     * Default validity period in years
     */
    private int validityPeriodYears = 2;

    /**
     * DocType configurations per template
     * Key: template name, Value: docType identifier
     */
    private Map<String, String> docTypes;

    /**
     * Namespace configurations per template
     * Key: template name, Value: default namespace
     */
    private Map<String, String> namespaces;

    /**
     * Field mapping configurations per template
     * Format: templateName.sourceField = targetNamespace:targetField
     */
    private Map<String, Map<String, String>> fieldMappings;
}