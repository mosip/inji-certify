/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import io.mosip.certify.core.validation.ValidOAuthTokenRequest;

/**
 * OAuth 2.0 Token Request DTO
 * Used for exchanging authorization code for access token
 * 
 * Based on RFC 6749 and OpenID4VCI specification
 */
@Data
@ValidOAuthTokenRequest
public class OAuthTokenRequest {

    /**
     * REQUIRED. Value MUST be set to "authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code", or "refresh_token"
     */
    @NotBlank(message = "grant_type is required")
    private String grant_type;

    /**
     * REQUIRED (for authorization_code grant). The authorization code received from the authorization server.
     */
    private String code;


    /**
     * REQUIRED (for PKCE). Code verifier used in the Proof Key for Code Exchange (PKCE) extension.
     */
    private String code_verifier;

    /**
     * REQUIRED (for refresh_token grant). The refresh token issued to the client.
     */
    private String refresh_token;

}
