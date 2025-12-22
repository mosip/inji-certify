/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
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
    @JsonProperty("grant_type")
    private String grantType;

    /**
     * REQUIRED (for authorization_code grant). The authorization code received from the authorization server.
     */
    @JsonProperty("code")
    private String code;


    /**
     * REQUIRED (for PKCE). Code verifier used in the Proof Key for Code Exchange (PKCE) extension.
     */
    @JsonProperty("code_verifier")
    private String codeVerifier;

    /**
     * REQUIRED (for refresh_token grant). The refresh token issued to the client.
     */
    @JsonProperty("refresh_token")
    private String refreshToken;

}
