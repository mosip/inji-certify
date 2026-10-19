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
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
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
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
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
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_emptyDocType_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void should_returnFalse_when_signatureAlgoIsMissing() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo(null);
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void should_returnFalse_when_signatureAlgoIsEmpty() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    /**
     * signatureCryptoSuite is mandatory so the request body is the same shape for every format, even
     * though an mdoc is signed with signatureAlgo alone.
     */
    @Test
    void should_returnFalse_when_signatureCryptoSuiteIsMissing() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void should_returnFalse_when_signatureCryptoSuiteIsEmpty() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    /**
     * The value itself is not validated: any crypto suite name is accepted for mso_mdoc.
     */
    @Test
    void should_returnTrue_when_signatureCryptoSuiteIsAnyValue() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("NotADeclaredSuite");
        assertTrue(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialTypeNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        config.setCredentialTypes(List.of("type"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_contextNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        config.setContextURLs(List.of("someContext URL"));
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_sdJwtVctNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        config.setSdJwtVct("sdJwtVct");
        assertFalse(MsoMdocCredentialConfigValidator.isValidCheck(config));
    }

    @Test
    void testIsValidCheck_credentialSubjectNotNull_returnsFalse() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setDocType("docType");
        config.setSignatureAlgo("ES256");
        config.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
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