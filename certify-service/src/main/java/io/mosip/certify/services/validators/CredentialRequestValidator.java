package io.mosip.certify.services.validators;

import io.mosip.certify.core.dto.CredentialRequest;

public interface CredentialRequestValidator {
    boolean isValidCheck(CredentialRequest credentialRequest);
}
