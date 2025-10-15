package io.mosip.certify.validators;

import io.mosip.certify.core.dto.CredentialRequest;

public class MsoMdocCredentialRequestValidator {
    public static boolean isValidCheck(CredentialRequest credentialRequest) {
        return credentialRequest.getDoctype() != null && !credentialRequest.getDoctype().isBlank();
    }
}
