package io.mosip.certify.validators;

import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.enums.CredentialFormat;

public class CredentialRequestValidator {
     public static boolean isValid(CredentialRequest credentialRequest) {
        if (credentialRequest.getFormat().equals(CredentialFormat.VC_LDP.toString())) {
            return LdpVcCredentialRequestValidator.isValidCheck(credentialRequest);
        } else if (credentialRequest.getFormat().equals(CredentialFormat.VC_MDOC.toString())) {
            return MsoMdocCredentialRequestValidator.isValidCheck(credentialRequest);
        } else if (credentialRequest.getFormat().equals(CredentialFormat.VC_DC_SD_JWT.toString()) || credentialRequest.getFormat().equals(CredentialFormat.VC_SD_JWT.toString())) {
            return SdJwtCredentialRequestValidator.isValidCheck(credentialRequest);
        }
        return false;
    }
}
