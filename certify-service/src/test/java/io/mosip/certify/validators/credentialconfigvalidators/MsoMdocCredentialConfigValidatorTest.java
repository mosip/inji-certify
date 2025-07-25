package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MsoMdocCredentialConfigValidatorTest {

    @Test
    void testIsValidCheck_validConfig_returnsTrue() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialType(null);
        config.setContext(null);
        config.setSdJwtVct(null);
        config.setCredentialSubject(null);
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_sdJwtClaimsPresent_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialType(null);
        config.setContext(null);
        config.setSdJwtVct(null);
        config.setCredentialSubject(null);
        config.setSdJwtClaims(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingDocType_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType(null);
        config.setSignatureCryptoSuite("suite");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptyDocType_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType("");
        config.setSignatureCryptoSuite("suite");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSignatureCryptoSuite_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType("docType");
        config.setSignatureCryptoSuite(null);
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptySignatureCryptoSuite_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialTypeNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialType("type");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_contextNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setContext("someContext URL");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_sdJwtVctNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setSdJwtVct("sdJwtVct");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialSubjectNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setDocType("docType");
        config.setSignatureCryptoSuite("suite");
        config.setCredentialSubject(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsConfigAlreadyPresent_present_returnsTrue() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("format");
        config.setDocType("docType");
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.of(config));
        assertTrue(MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsConfigAlreadyPresent_notPresent_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("format");
        config.setDocType("docType");
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.empty());
        assertFalse(MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }
}

