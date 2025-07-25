package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LdpVcCredentialConfigValidatorTest {

    @Test
    void testIsValidCheck_missingContext_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setContext(null);
        config.setCredentialType("VerifiableCredential,TestVerifiableCredential");
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSignatureCryptoSuite_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setContext("https://example.org/context");
        config.setCredentialType("VerifiableCredential,TestVerifiableCredential");
        config.setSignatureCryptoSuite(null);
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_allValidFields_returnsTrue() {
        CredentialConfig config = new CredentialConfig();
        config.setContext("https://example.org/context");
        config.setCredentialType("VerifiableCredential,TestVerifiableCredential");
        config.setSignatureCryptoSuite("Ed25519Signature2020");
        config.setDocType(null);
        config.setSdJwtVct(null);
        config.setMsoMdocClaims(null);
        config.setSdJwtClaims(null);
        assertTrue(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptyContext_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setContext("");
        config.setCredentialType("VerifiableCredential,TestVerifiableCredential");
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingCredentialType_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setContext("https://example.org/context");
        config.setCredentialType(null);
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptyCredentialType_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setContext("https://example.org/context");
        config.setCredentialType("");
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_docTypeNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setContext("https://example.org/context");
        config.setCredentialType("VerifiableCredential,TestVerifiableCredential");
        config.setDocType("docType");
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_claimsNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setContext("https://example.org/context");
        config.setCredentialType("TestType");
        config.setMsoMdocClaims(new HashMap<>());
        config.setSdJwtClaims(new HashMap<>());
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_sdJwtVctNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setContext("https://example.org/context");
        config.setCredentialType("VerifiableCredential,TestVerifiableCredential");
        config.setSdJwtVct("sdJwtVct");
        assertFalse(LdpVcCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsConfigAlreadyPresent_whenPresent_returnsTrue() {
        CredentialConfig config = Mockito.mock(CredentialConfig.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndCredentialTypeAndContext(
                config.getCredentialFormat(),
                config.getCredentialType(),
                config.getContext()
        )).thenReturn(Optional.of(config));

        boolean result = LdpVcCredentialConfigValidator.isConfigAlreadyPresent(config, repo);
        assertTrue(result);
    }

    @Test
    void testIsConfigAlreadyPresent_whenNotPresent_returnsFalse() {
        CredentialConfig config = Mockito.mock(CredentialConfig.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndCredentialTypeAndContext(
                config.getCredentialFormat(),
                config.getCredentialType(),
                config.getContext()
        )).thenReturn(Optional.empty());

        boolean result = LdpVcCredentialConfigValidator.isConfigAlreadyPresent(config, repo);
        assertFalse(result);
    }
}

