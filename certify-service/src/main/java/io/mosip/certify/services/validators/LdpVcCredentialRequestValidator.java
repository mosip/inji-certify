package io.mosip.certify.services.validators;

import io.mosip.certify.core.dto.CredentialRequest;

public class LdpVcCredentialRequestValidator {
    public static boolean isValidCheck(CredentialRequest credentialRequest) {
        return credentialRequest.getCredential_definition() != null;
    }
}
