package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SdJwtCredentialConfigValidatorTest {

    @Test
    void testIsValidCheck_validConfig_returnsTrue() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialType(null);
        config.setContext(null);
        config.setDocType(null);
        config.setCredentialSubject(null);
        assertTrue(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_msoMdocClaimsPreset_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialType(null);
        config.setContext(null);
        config.setDocType(null);
        config.setCredentialSubject(null);
        config.setMsoMdocClaims(new HashMap<>());
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSdJwtVct_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct(null);
        config.setSignatureAlgo("algoValue");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptySdJwtVct_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("");
        config.setSignatureAlgo("algoValue");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSignatureAlgo_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo(null);
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptySignatureAlgo_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialTypeNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialType("type");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_contextNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setContext("someContextURL.com");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_docTypeNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setDocType("docType");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialSubjectNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialSubject(new HashMap<>());
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsConfigAlreadyPresent_present_returnsTrue() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("format");
        config.setSdJwtVct("vctValue");
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndSdJwtVct("format", "vctValue"))
                .thenReturn(Optional.of(config));
        assertTrue(SdJwtCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsConfigAlreadyPresent_notPresent_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("format");
        config.setSdJwtVct("vctValue");
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndSdJwtVct("format", "vctValue"))
                .thenReturn(Optional.empty());
        assertFalse(SdJwtCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsValidCheck_msoMdocClaimsNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setMsoMdocClaims(new HashMap<>());
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_signatureCryptoSuiteNotNull_returnsFalse() {
        CredentialConfig config = new CredentialConfig();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setSignatureCryptoSuite("suiteValue");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }
}

