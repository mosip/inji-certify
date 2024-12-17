package io.mosip.certify.validators;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialRequest;

public class CredentialRequestValidator {
     public static boolean isValid(CredentialRequest credentialRequest) {
        if (credentialRequest.getFormat().equals(VCFormats.LDP_VC)) {
            return LdpVcCredentialRequestValidator.isValidCheck(credentialRequest);
        } else if (credentialRequest.getFormat().equals(VCFormats.MSO_MDOC)) {
            return MsoMdocCredentialRequestValidator.isValidCheck(credentialRequest);
        }
        return false;
    }
}
