package io.mosip.certify.core.validators;

import io.mosip.certify.core.dto.CredentialRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class MsoMdocCredentialRequestValidatorTest {

    private MsoMdocCredentialRequestValidator validator;
    private CredentialRequest request;

    @BeforeEach
    void setUp() {
        validator = new MsoMdocCredentialRequestValidator();
        request = new CredentialRequest();
    }

    @Test
    void isValidCheck_ValidRequest_ReturnsTrue() {
        request.setDoctype("org.iso.18013.5.1.mDL");
        Map<String, Object> claims = new HashMap<>();
        claims.put("given_name", "John");
        request.setClaims(claims);
        assertTrue(validator.isValidCheck(request), "Should be true for a valid request with doctype and claims.");
    }

    @Test
    void isValidCheck_NullDoctype_ReturnsFalse() {
        request.setDoctype(null);
        Map<String, Object> claims = new HashMap<>();
        claims.put("given_name", "John");
        request.setClaims(claims);
        assertFalse(validator.isValidCheck(request), "Should be false when doctype is null.");
    }

    @Test
    void isValidCheck_EmptyDoctype_ReturnsFalse() {
        request.setDoctype("");
        Map<String, Object> claims = new HashMap<>();
        claims.put("given_name", "John");
        request.setClaims(claims);
        assertFalse(validator.isValidCheck(request), "Should be false when doctype is empty.");
    }

    @Test
    void isValidCheck_BlankDoctype_ReturnsFalse() {
        request.setDoctype("   ");
        Map<String, Object> claims = new HashMap<>();
        claims.put("given_name", "John");
        request.setClaims(claims);
        assertFalse(validator.isValidCheck(request), "Should be false when doctype is blank.");
    }

    @Test
    void isValidCheck_NullClaims_ReturnsFalse() {
        request.setDoctype("org.iso.18013.5.1.mDL");
        request.setClaims(null);
        assertFalse(validator.isValidCheck(request), "Should be false when claims are null.");
    }

    @Test
    void isValidCheck_EmptyClaims_ReturnsFalse() {
        request.setDoctype("org.iso.18013.5.1.mDL");
        request.setClaims(Collections.emptyMap());
        assertFalse(validator.isValidCheck(request), "Should be false when claims are empty.");
    }

    @Test
    void isValidCheck_NullRequest_ThrowsNullPointerException() {
        assertThrows(NullPointerException.class, () -> {
            validator.isValidCheck(null);
        }, "Should throw NullPointerException when the request object is null.");
    }
}
