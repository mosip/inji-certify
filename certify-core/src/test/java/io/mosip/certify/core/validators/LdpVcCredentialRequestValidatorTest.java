package io.mosip.certify.core.validators;

import io.mosip.certify.core.dto.CredentialDefinition;
import io.mosip.certify.core.dto.CredentialRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LdpVcCredentialRequestValidatorTest {

    private LdpVcCredentialRequestValidator validator;
    private CredentialRequest request;

    @BeforeEach
    void setUp() {
        validator = new LdpVcCredentialRequestValidator();
        request = new CredentialRequest();
    }

    @Test
    void isValidCheck_ValidRequest_ReturnsTrue() {
        request.setCredential_definition(new CredentialDefinition());
        assertTrue(validator.isValidCheck(request), "Should be true for a request with a non-null credential definition.");
    }

    @Test
    void isValidCheck_NullDefinition_ReturnsFalse() {
        request.setCredential_definition(null);
        assertFalse(validator.isValidCheck(request), "Should be false for a request with a null credential definition.");
    }

    @Test
    void isValidCheck_NullRequest_ThrowsNullPointerException() {
        assertThrows(NullPointerException.class, () -> {
            validator.isValidCheck(null);
        }, "Should throw NullPointerException when the request object is null.");
    }
}
