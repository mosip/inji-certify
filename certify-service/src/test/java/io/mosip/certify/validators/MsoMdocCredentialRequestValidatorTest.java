package io.mosip.certify.validators;

import io.mosip.certify.core.dto.CredentialRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class MsoMdocCredentialRequestValidatorTest {
    @InjectMocks
    MsoMdocCredentialRequestValidator msoMdocCredentialRequestValidator;

    @Test
    public void checkMsoMdocValidatorWithValidCredentialRequest_thenPass() {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setDoctype("mdoc-doctype");
        credentialRequest.setClaims(Map.of("client_id", "test-client-id"));
        assertTrue(MsoMdocCredentialRequestValidator.isValidCheck(credentialRequest));
    }

    @Test
    public void checkMsoMdocValidatorWithInvalidDoctype_thenFail() {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setClaims(Map.of("client_id", "test-client-id"));
        assertFalse(MsoMdocCredentialRequestValidator.isValidCheck(credentialRequest));
    }

    @Test
    public void checkMsoMdocValidatorWithEmptyClaims_thenFail() {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setDoctype("mdoc-doctype");
        assertFalse(MsoMdocCredentialRequestValidator.isValidCheck(credentialRequest));
    }
}
