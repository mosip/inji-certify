package io.mosip.certify.validators;

import io.mosip.certify.core.dto.CredentialRequest;

public class SdJwtCredentialRequestValidator {
    public static boolean isValidCheck(CredentialRequest credentialRequest) {
        return credentialRequest.getSdJwtVct() != null && !credentialRequest.getSdJwtVct().isEmpty();
    }
    
}
