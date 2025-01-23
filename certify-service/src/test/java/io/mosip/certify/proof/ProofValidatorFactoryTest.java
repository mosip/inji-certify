package io.mosip.certify.proof;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ProofValidatorFactoryTest {

    @InjectMocks
    private ProofValidatorFactory proofValidatorFactory;

    @Mock
    private ProofValidator jwtProofValidator;

    @Mock
    private ProofValidator anotherProofValidator;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        proofValidatorFactory = new ProofValidatorFactory();
        ReflectionTestUtils.setField(proofValidatorFactory, "proofValidators", Arrays.asList(jwtProofValidator, anotherProofValidator));
    }

    @Test
    void testGetProofValidator_ValidProofType() {
        // Arrange
        String validProofType = "jwt";  // Assuming "jwt" is a valid proof type
        when(jwtProofValidator.getProofType()).thenReturn("jwt");
        when(anotherProofValidator.getProofType()).thenReturn("another-proof");

        // Act
        ProofValidator result = proofValidatorFactory.getProofValidator(validProofType);

        // Assert
        assertNotNull(result, "The proof validator should not be null.");
        assertEquals(jwtProofValidator, result, "The correct proof validator should be returned.");
    }

    @Test
    void testGetProofValidator_InvalidProofType() {
        // Arrange
        String invalidProofType = "invalid-proof";  // Invalid proof type
        when(jwtProofValidator.getProofType()).thenReturn("jwt");
        when(anotherProofValidator.getProofType()).thenReturn("another-proof");

        // Act and Assert
        CertifyException thrown = assertThrows(CertifyException.class, () ->
                        proofValidatorFactory.getProofValidator(invalidProofType),
                "Expected CertifyException to be thrown for invalid proof type."
        );

        assertEquals(ErrorConstants.UNSUPPORTED_PROOF_TYPE, thrown.getErrorCode(),
                "The error code should be the correct unsupported proof type error.");
    }
}
