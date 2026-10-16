package io.mosip.certify.config;

import io.mosip.certify.utils.CredentialConfigMetadataResolver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

/**
 * Reads mosip.certify.credential-config.credential-signing-alg-values-supported once, so every class that
 * checks or resolves a signing algorithm against it sees the same values.
 */
@Configuration
public class CredentialSigningAlgConfig {

    @Bean
    public CredentialConfigMetadataResolver.DeclaredSigningAlgs declaredSigningAlgs(
            @Value("#{${mosip.certify.credential-config.credential-signing-alg-values-supported}}") Map<String, Object> declared) {
        return CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(declared);
    }
}
