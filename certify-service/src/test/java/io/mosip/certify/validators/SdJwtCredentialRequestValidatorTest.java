package io.mosip.certify.validators;

import io.mosip.certify.core.dto.CredentialRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Map;

import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class SdJwtCredentialRequestValidatorTest {
    @InjectMocks
    SdJwtCredentialRequestValidator sdJwtCredentialRequestValidator;

    @Test
    public void checkMsoMdocValidatorWithValidCredentialRequest_thenPass() {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setVct("sd_jwt_vct");
        credentialRequest.setClaims(Map.of("client_id", "test-client-id"));
        assertTrue(SdJwtCredentialRequestValidator.isValidCheck(credentialRequest));
    }

    @Test
    public void checkMsoMdocValidatorWithInvalidDoctype_thenFail() {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setClaims(Map.of("client_id", "test-client-id"));
        assertFalse(SdJwtCredentialRequestValidator.isValidCheck(credentialRequest));
    }
}