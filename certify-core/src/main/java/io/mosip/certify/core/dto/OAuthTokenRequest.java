/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * OAuth 2.0 Token Request DTO
 * Used for exchanging authorization code for access token
 * 
 * Based on RFC 6749 and OpenID4VCI specification
 */
@Data
public class OAuthTokenRequest {

    /**
     * REQUIRED. Value MUST be set to "authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code", or "refresh_token"
     */
    @JsonProperty("grant_type")
    private String grantType;

    /**
     * REQUIRED (for authorization_code grant). The authorization code received from the authorization server.
     */
    @JsonProperty("code")
    private String code;

    /**
     * REQUIRED (for pre-authorized_code grant). The pre-authorized code provided by the Credential Issuer.
     */
    @JsonProperty("pre-authorized_code")
    private String preAuthorizedCode;

    /**
     * REQUIRED (for authorization_code grant). MUST be identical to the redirect_uri parameter included in the authorization request.
     */
    @JsonProperty("redirect_uri")
    private String redirectUri;

    /**
     * REQUIRED (if client authentication is not performed via other means). The client identifier.
     */
    @JsonProperty("client_id")
    private String clientId;

    /**
     * OPTIONAL. The client secret (if client authentication is performed via client_secret_post).
     */
    @JsonProperty("client_secret")
    private String clientSecret;

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

    /**
     * OPTIONAL. The user PIN associated with the pre-authorized code (for pre-authorized_code grant).
     */
    @JsonProperty("user_pin")
    private String userPin;
}
