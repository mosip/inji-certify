package io.mosip.certify.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "mosip.certify")
@Getter
@Setter
public class IndexedAttributesConfig {
    /**
     * Holds the mappings from a desired attribute name (key) to the
     * JSONPath expression (value) used to extract it from the source data.
     */
    private Map<String, String> indexedMappings = new HashMap<>();
}