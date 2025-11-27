package io.mosip.certify.validators;

import io.mosip.certify.core.dto.CredentialRequest;

public class LdpVcCredentialRequestValidator {
    public static boolean isValidCheck(CredentialRequest credentialRequest) {
        return credentialRequest.getCredential_definition() != null &&
               credentialRequest.getCredential_definition().getContext() != null &&
               !credentialRequest.getCredential_definition().getContext().isEmpty() &&
               credentialRequest.getCredential_definition().getType() != null &&
               !credentialRequest.getCredential_definition().getType().isEmpty();
    }
}
