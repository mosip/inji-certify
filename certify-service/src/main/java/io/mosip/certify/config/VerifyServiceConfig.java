package io.mosip.certify.config;

import io.mosip.certify.core.dto.PresentationDefinition;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "mosip.certify.verify.service")
public class VerifyServiceConfig {

    private PresentationDefinition presentationDefinition;
}

