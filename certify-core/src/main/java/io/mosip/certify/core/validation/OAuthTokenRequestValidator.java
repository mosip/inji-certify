/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.validation;

import io.mosip.certify.core.dto.OAuthTokenRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.util.StringUtils;

public class OAuthTokenRequestValidator implements ConstraintValidator<ValidOAuthTokenRequest, OAuthTokenRequest> {
    
    @Override
    public boolean isValid(OAuthTokenRequest value, ConstraintValidatorContext context) {
        if (value == null) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("OAuth token request is required")
                   .addConstraintViolation();
            return false;
        }

        // Validate grant_type
        if (!StringUtils.hasText(value.getGrant_type())) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("grant_type is required")
                   .addPropertyNode("grant_type")
                   .addConstraintViolation();
            return false;
        }

        // Only support authorization_code grant type for now
        if (!"authorization_code".equals(value.getGrant_type())) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Unsupported grant_type: " + value.getGrant_type() + ". Only 'authorization_code' is supported")
                   .addPropertyNode("grant_type")
                   .addConstraintViolation();
            return false;
        }

        // For authorization_code grant, validate required fields
        boolean hasCode = StringUtils.hasText(value.getCode());
        boolean hasCodeVerifier = StringUtils.hasText(value.getCode_verifier());

        if (!hasCode) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("code is required for authorization_code grant")
                   .addPropertyNode("code")
                   .addConstraintViolation();
            return false;
        }

        if (!hasCodeVerifier) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("code_verifier is required for PKCE")
                   .addPropertyNode("code_verifier")
                   .addConstraintViolation();
            return false;
        }

        // redirect_uri is optional since we don't support redirect_to_web
        // client_id is optional for public clients per RFC 7636 Section 3.2
        // No validation needed for client_id or redirect_uri presence

        return true;
    }
}
