package io.mosip.certify.core.validators;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialRequest;

public class CredentialRequestValidatorFactory {
     public boolean isValid(CredentialRequest credentialRequest) {
        if (credentialRequest.getFormat().equals(VCFormats.LDP_VC)) {
            return new LdpVcCredentialRequestValidator().isValidCheck(credentialRequest);
        } else if (credentialRequest.getFormat().equals(VCFormats.MSO_MDOC)) {
            return new MsoMdocCredentialRequestValidator().isValidCheck(credentialRequest);
        }
        return false;
    }
}
