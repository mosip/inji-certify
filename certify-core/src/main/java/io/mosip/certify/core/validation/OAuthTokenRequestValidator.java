/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.validation;

import io.mosip.certify.core.dto.OAuthTokenRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class OAuthTokenRequestValidator implements ConstraintValidator<ValidOAuthTokenRequest, OAuthTokenRequest> {
    
    @Override
    public boolean isValid(OAuthTokenRequest value, ConstraintValidatorContext context) {
        if (value == null) {
            return true;
        }

        // Validate grant_type
        if (!hasText(value.getGrantType())) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("grant_type is required")
                   .addPropertyNode("grantType")
                   .addConstraintViolation();
            return false;
        }

        // Only support authorization_code grant type for now
        if (!"authorization_code".equals(value.getGrantType())) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Unsupported grant_type: " + value.getGrantType() + ". Only 'authorization_code' is supported")
                   .addPropertyNode("grantType")
                   .addConstraintViolation();
            return false;
        }

        // For authorization_code grant, validate required fields
        if ("authorization_code".equals(value.getGrantType())) {
            boolean hasCode = hasText(value.getCode());
            boolean hasRedirectUri = hasText(value.getRedirectUri());
            boolean hasCodeVerifier = hasText(value.getCodeVerifier());

            if (!hasCode) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("code is required for authorization_code grant")
                       .addPropertyNode("code")
                       .addConstraintViolation();
                return false;
            }

            if (!hasRedirectUri) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("redirect_uri is required for authorization_code grant")
                       .addPropertyNode("redirectUri")
                       .addConstraintViolation();
                return false;
            }

            if (!hasCodeVerifier) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("code_verifier is required for PKCE")
                       .addPropertyNode("codeVerifier")
                       .addConstraintViolation();
                return false;
            }
            
            // client_id is optional for public clients per RFC 7636 Section 3.2
            // No validation needed for client_id presence
        }

        return true;
    }

    private boolean hasText(String s) {
        return s != null && !s.trim().isEmpty();
    }
}
