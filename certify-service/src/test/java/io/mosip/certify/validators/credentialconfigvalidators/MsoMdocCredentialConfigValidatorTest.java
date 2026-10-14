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

class MsoMdocCredentialConfigValidatorTest {

    @Test
    void testIsValidCheck_validConfig_returnsTrue() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setSdJwtVct(null);
        config.setClaims(null);
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_sdJwtClaimsPresent_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setCredentialTypes(null);
        config.setContextURLs(null);
        config.setSdJwtVct(null);
        config.setClaims(null);
        config.setSdJwtClaims(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_missingDocType_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType(null);
        config.setSignatureAlgo("ES256");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptyDocType_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("");
        config.setSignatureAlgo("ES256");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void should_returnFalse_when_signatureAlgoIsMissing() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo(null);
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void should_returnFalse_when_signatureAlgoIsEmpty() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    /**
     * An mdoc is signed with signatureAlgo alone, so a crypto suite is not required. A request that sends
     * one is rejected by the service as an invalid request, not reported as a missing mandatory field.
     */
    @Test
    void should_returnTrue_when_signatureCryptoSuiteIsAbsent() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialTypeNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setCredentialTypes(List.of("type"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_contextNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setContextURLs(List.of("someContext URL"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_sdJwtVctNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSdJwtVct("sdJwtVct");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialSubjectNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setClaims(new HashMap<>());
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsConfigAlreadyPresent_present_returnsTrue() {
        CredentialConfigurationDTO config = Mockito.mock(CredentialConfigurationDTO.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getDocType()).thenReturn("docType");
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.of(new io.mosip.certify.entity.CredentialConfig()));
        assertTrue(MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }

    @Test
    void testIsConfigAlreadyPresent_notPresent_returnsFalse() {
        CredentialConfigurationDTO config = Mockito.mock(CredentialConfigurationDTO.class);
        CredentialConfigRepository repo = Mockito.mock(CredentialConfigRepository.class);
        Mockito.when(config.getCredentialFormat()).thenReturn("format");
        Mockito.when(config.getDocType()).thenReturn("docType");
        Mockito.when(repo.findByCredentialFormatAndDocType("format", "docType"))
                .thenReturn(Optional.empty());
        assertFalse(MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(config, repo));
    }
}