package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LdpVcCredentialConfigValidatorTest {

    @Test
    void testIsValidCheck_missingContext_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setContextURLs(null);
        config.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSignatureCryptoSuite_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setContextURLs(List.of("https://example.org/context"));
        config.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        config.setSignatureCryptoSuite(null);
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_allValidFields_returnsTrue() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setContextURLs(List.of("https://example.org/context"));
        config.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        config.setSignatureCryptoSuite("Ed25519Signature2020");
        config.setSignatureAlgo("EdDSA");
        config.setDocType(null);
        config.setSdJwtVct(null);
        config.setMsoMdocClaims(null);
        config.setSdJwtClaims(null);
        assertTrue(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptyContext_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setContextURLs(List.of(""));
        config.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingCredentialType_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setContextURLs(List.of("https://example.org/context"));
        config.setCredentialTypes(null);
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptyCredentialType_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setContextURLs(List.of("https://example.org/context"));
        config.setCredentialTypes(List.of());
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_docTypeNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setContextURLs(List.of("https://example.org/context"));
        config.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        config.setDocType("docType");
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_claimsNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setContextURLs(List.of("https://example.org/context"));
        config.setCredentialTypes(List.of("TestType"));
        config.setMsoMdocClaims(new HashMap<>());
        config.setSdJwtClaims(new HashMap<>());
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_sdJwtVctNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setContextURLs(List.of("https://example.org/context"));
        config.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        config.setSdJwtVct("sdJwtVct");
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsConfigAlreadyPresent_whenPresent_returnsTrue() {
        CredentialConfigurationDTO config = Mockito.mock(CredentialConfigurationDTO.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getCredentialTypes()).thenReturn(List.of("type1", "type2"));
        Mockito.when(config.getContextURLs()).thenReturn(List.of("context1", "context2"));
        String credentialTypes = String.join(",", config.getCredentialTypes());
        String context = String.join(",", config.getContextURLs());
        Mockito.when(repo.findByCredentialFormatAndCredentialTypeAndContext(
                config.getCredentialFormat(),
                credentialTypes,
                context
        )).thenReturn(Optional.of(new io.mosip.certify.entity.CredentialConfig()));

        boolean result = LdpVcCredentialConfigValidator.isConfigAlreadyPresent(config, repo);
        assertTrue(result);
    }

    @Test
    void testIsConfigAlreadyPresent_whenNotPresent_returnsFalse() {
        CredentialConfigurationDTO config = Mockito.mock(CredentialConfigurationDTO.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getCredentialTypes()).thenReturn(List.of("type1", "type2"));
        Mockito.when(config.getContextURLs()).thenReturn(List.of("context1", "context2"));
        String credentialTypes = String.join(",", config.getCredentialTypes());
        String context = String.join(",", config.getContextURLs());
        Mockito.when(repo.findByCredentialFormatAndCredentialTypeAndContext(
                config.getCredentialFormat(),
                credentialTypes,
                context
        )).thenReturn(Optional.empty());

        boolean result = LdpVcCredentialConfigValidator.isConfigAlreadyPresent(config, repo);
        assertFalse(result);
    }
}
