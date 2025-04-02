package io.mosip.certify.core.validators;

import io.mosip.certify.core.dto.CredentialRequest;

public class MsoMdocCredentialRequestValidator implements CredentialRequestValidator {
    public boolean isValidCheck(CredentialRequest credentialRequest) {
        if (credentialRequest.getDoctype() == null || credentialRequest.getDoctype().isBlank()) {
            return false;
        }
        return credentialRequest.getClaims() != null && !credentialRequest.getClaims().isEmpty();
    }
}
