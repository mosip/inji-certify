package io.mosip.certify.core.validators;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialRequest;
import lombok.extern.slf4j.Slf4j;

//todo replace usage of existing validators with this factory
@Slf4j
public class CredentialRequestValidatorFactory {
     public boolean isValid(CredentialRequest credentialRequest) {
        switch (credentialRequest.getFormat()) {
            case VCFormats.LDP_VC:
                return new LdpVcCredentialRequestValidator().isValidCheck(credentialRequest);
            case VCFormats.MSO_MDOC:
                return new MsoMdocCredentialRequestValidator().isValidCheck(credentialRequest);
            case VCFormats.LDP_SD_JWT:
                return new SDJWTVcCredentialRequestValidator().isValidCheck(credentialRequest);
            default:
                log.debug("Unsupported or Invalid request format {} ", credentialRequest.getFormat());
                return false;
        }
        
    }
}
