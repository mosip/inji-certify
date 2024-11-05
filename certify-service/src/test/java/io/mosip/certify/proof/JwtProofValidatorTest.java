package io.mosip.certify.proof;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import io.mosip.certify.core.dto.CredentialProof;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.*;

class JwtProofValidatorTest {

    private JwtProofValidator jwtProofValidator;

    @Mock
    private CredentialProof credentialProof;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        jwtProofValidator = new JwtProofValidator();
    }

    @Test
    void testValidateWithNullJwt() {

        when(credentialProof.getJwt()).thenReturn(null);


        boolean result = jwtProofValidator.validate("client-id", "nonce", credentialProof);


        assertFalse(result, "Expected validation to fail for null JWT");
    }

    @Test
    void testValidateWithBlankJwt() {

        when(credentialProof.getJwt()).thenReturn("");


        boolean result = jwtProofValidator.validate("client-id", "nonce", credentialProof);


        assertFalse(result, "Expected validation to fail for blank JWT");
    }

}
