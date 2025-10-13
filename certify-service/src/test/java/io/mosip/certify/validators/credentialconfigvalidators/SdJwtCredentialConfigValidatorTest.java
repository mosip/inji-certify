package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
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
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setDocType(null);
        config.setCredentialSubjectDefinition(null);
        assertTrue(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_msoMdocClaimsPreset_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setDocType(null);
        config.setCredentialSubjectDefinition(null);
        config.setMsoMdocClaims(new HashMap<>());
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSdJwtVct_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct(null);
        config.setSignatureAlgo("algoValue");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptySdJwtVct_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("");
        config.setSignatureAlgo("algoValue");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingSignatureAlgo_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo(null);
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptySignatureAlgo_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialTypeNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialTypes(java.util.Collections.singletonList("type"));
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_contextNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setContextURLs(java.util.Collections.singletonList("someContextURL.com"));
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_docTypeNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setDocType("docType");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialSubjectNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setCredentialSubjectDefinition(new HashMap<>());
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsConfigAlreadyPresent_present_returnsTrue() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialFormat("format");
        config.setSdJwtVct("vctValue");
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndSdJwtVct("format", "vctValue"))
                .thenReturn(Optional.of(new CredentialConfig()));
        assertTrue(SdJwtCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsConfigAlreadyPresent_notPresent_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialFormat("format");
        config.setSdJwtVct("vctValue");
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(repo.findByCredentialFormatAndSdJwtVct("format", "vctValue"))
                .thenReturn(Optional.empty());
        assertFalse(SdJwtCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsValidCheck_msoMdocClaimsNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setMsoMdocClaims(new HashMap<>());
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_signatureCryptoSuiteNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setSdJwtVct("vctValue");
        config.setSignatureAlgo("algoValue");
        config.setSignatureCryptoSuite("suiteValue");
        assertFalse(SdJwtCredentialConfigValidator.isValidCheck(config));
    }
}
