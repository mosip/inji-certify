package io.mosip.certify.core.validators;

import io.mosip.certify.core.dto.CredentialRequest;

public class MsoMdocCredentialRequestValidator implements CredentialRequestValidator {
    @Override
    public boolean isValidCheck(CredentialRequest credentialRequest) {
        if (credentialRequest.getDoctype() == null || credentialRequest.getDoctype().isBlank()) {
            return false;
        }
        if (credentialRequest.getClaims() == null || credentialRequest.getClaims().isEmpty())
            return false;
        return true;
    }
}
