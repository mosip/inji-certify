package io.mosip.certify.services.validators;

import io.mosip.certify.core.dto.CredentialRequest;

public class MsoMdocCredentialRequestValidator {
    public static boolean isValidCheck(CredentialRequest credentialRequest) {
        if (credentialRequest.getDoctype() == null || credentialRequest.getDoctype().isBlank()) {
            return false;
        }
        return credentialRequest.getClaims() != null && !credentialRequest.getClaims().isEmpty();
    }
}
