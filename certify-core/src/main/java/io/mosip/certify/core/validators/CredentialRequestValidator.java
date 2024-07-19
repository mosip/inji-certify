package io.mosip.certify.core.validators;

import io.mosip.certify.core.dto.CredentialRequest;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class CredentialRequestValidator implements ConstraintValidator<ValidCredentialRequest, CredentialRequest> {

    @Override
    public void initialize(ValidCredentialRequest constraintAnnotation) {
        System.out.println("output");
        ConstraintValidator.super.initialize(constraintAnnotation);
    }

    public boolean isValid(CredentialRequest credentialRequest,
                           ConstraintValidatorContext context) {
        //TODO: Extract formats as constant
        System.out.println("validating credential request");
        if (credentialRequest.getFormat().equals("mso_mdoc")) {
            if (credentialRequest.getDoctype() == null || credentialRequest.getDoctype().isEmpty() || credentialRequest.getClaims() == null || credentialRequest.getClaims().isEmpty()) {
                return false;
            }
        } else if (credentialRequest.getFormat().equals("ldp_Vc") && credentialRequest.getCredential_definition() == null) {
            return false;
        }

        System.out.println("validated all");
        //TODO: Check if proof dto validation works or not
        return true;
    }
}

