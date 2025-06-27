package io.mosip.certify.validators;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialDefinition;
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
public class LdpVcCredentialRequestValidatorTest {
    @InjectMocks
    LdpVcCredentialRequestValidator ldpVcCredentialRequestValidator;

    @Test
    public void checkLdpVcValidatorWithValidCredentialRequest_thenPass() {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setFormat(VCFormats.LDP_VC);
        credentialRequest.setCredential_definition(new CredentialDefinition());
        assertTrue(LdpVcCredentialRequestValidator.isValidCheck(credentialRequest));
    }

    @Test
    public void checkLdpVcValidatorTestWithInvalidCredentialDefinition_thenFail() {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setFormat(VCFormats.LDP_VC);
        credentialRequest.setClaims(Map.of("client_id", "test-client-id"));
        assertFalse(LdpVcCredentialRequestValidator.isValidCheck(credentialRequest));
    }
}
