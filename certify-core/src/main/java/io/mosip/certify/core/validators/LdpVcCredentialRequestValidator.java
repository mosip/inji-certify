package io.mosip.certify.core.validators;

import io.mosip.certify.core.dto.CredentialRequest;

public class LdpVcCredentialRequestValidator implements CredentialRequestValidator {
    @Override
    public boolean isValidCheck(CredentialRequest credentialRequest) {
        return credentialRequest.getCredential_definition() != null;
    }
}
