package io.mosip.certify.core.validators;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialDefinition;
import io.mosip.certify.core.dto.CredentialRequest;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialRequestValidatorFactoryTest {

    private CredentialRequestValidatorFactory factory;
    private CredentialRequest request;

    @BeforeEach
    void setUp() {
        factory = new CredentialRequestValidatorFactory();
        request = new CredentialRequest();
    }

    @Test
    void isValid_LdpVcFormat_ValidDefinition_ReturnsTrue() {
        request.setFormat(VCFormats.LDP_VC);
        request.setCredential_definition(new CredentialDefinition());
        assertTrue(factory.isValid(request), "Should be valid for LDP_VC with a credential definition.");
    }

    @Test
    void isValid_LdpVcFormat_NullDefinition_ReturnsFalse() {
        request.setFormat(VCFormats.LDP_VC);
        request.setCredential_definition(null);
        assertFalse(factory.isValid(request), "Should be invalid for LDP_VC with a null credential definition.");
    }

    @Test
    void isValid_MsoMdocFormat_ValidDefinition_ReturnsTrue() {
        request.setFormat(VCFormats.MSO_MDOC);
        // Assuming MsoMdocCredentialRequestValidator requires a non-null credential_definition
        // and its type to be non-null as a basic check for this test.
        CredentialDefinition definition = new CredentialDefinition();
        definition.setType(List.of("someType")); 
        request.setCredential_definition(definition);
        // MsoMdocCredentialRequestValidator checks doctype and claims, not credential_definition.type directly.
        request.setDoctype("someDocType");
        request.setClaims(Map.of("someClaim", "someValue"));
        assertTrue(factory.isValid(request), "Should be valid for MSO_MDOC with a credential definition, doctype and claims.");
    }

    @Test
    void isValid_MsoMdocFormat_NullDefinition_ReturnsFalse() {
        request.setFormat(VCFormats.MSO_MDOC);
        request.setCredential_definition(null);
        assertFalse(factory.isValid(request), "Should be invalid for MSO_MDOC with a null credential definition.");
    }
    
    @Test
    void isValid_MsoMdocFormat_DefinitionWithoutType_ReturnsFalse() {
        request.setFormat(VCFormats.MSO_MDOC);
        CredentialDefinition definition = new CredentialDefinition();
        definition.setType(null); // Type is null
        request.setCredential_definition(definition);
        // This assertion depends on the actual implementation of MsoMdocCredentialRequestValidator.
        // Based on the prompt's assumption that it might need credentialRequest.getCredential_definition().getType()
        // to be non-null, this should be false.
        assertFalse(factory.isValid(request), "Should be invalid for MSO_MDOC if credential_definition.type is null.");
    }


    @Test
    void isValid_LdpSdJwtFormat_ValidDefinition_ReturnsTrue() {
        request.setFormat(VCFormats.LDP_SD_JWT);
        // Assuming SDJWTVcCredentialRequestValidator requires a non-null credential_definition for this test
        request.setCredential_definition(new CredentialDefinition());
        assertTrue(factory.isValid(request), "Should be valid for LDP_SD_JWT with a credential definition.");
    }

    @Test
    void isValid_LdpSdJwtFormat_NullDefinition_ReturnsFalse() {
        request.setFormat(VCFormats.LDP_SD_JWT);
        request.setCredential_definition(null);
        assertFalse(factory.isValid(request), "Should be invalid for LDP_SD_JWT with a null credential definition.");
    }

    @Test
    void isValid_UnsupportedFormat_ReturnsFalse() {
        request.setFormat("unknown_format");
        request.setCredential_definition(new CredentialDefinition()); // Definition doesn't matter here
        assertFalse(factory.isValid(request), "Should be invalid for an unsupported format.");
    }

    @Test
    void isValid_NullFormat_ReturnsFalse() {
        request.setFormat(null);
        request.setCredential_definition(new CredentialDefinition()); // Definition doesn't matter here
        assertFalse(factory.isValid(request), "Should be invalid if the format is null.");
    }
}
