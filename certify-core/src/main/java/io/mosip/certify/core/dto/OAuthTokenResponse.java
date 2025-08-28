/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * OAuth 2.0 Token Response DTO
 * Returned when exchanging authorization code for access token
 * 
 * Based on RFC 6749 and OpenID4VCI specification
 */
@Data
public class OAuthTokenResponse {

    /**
     * REQUIRED. The access token issued by the authorization server.
     */
    @JsonProperty("access_token")
    private String accessToken;

    /**
     * REQUIRED. The type of the token issued. Value is case insensitive. Typically "Bearer".
     */
    @JsonProperty("token_type")
    private String tokenType;

    /**
     * RECOMMENDED. The lifetime in seconds of the access token.
     */
    @JsonProperty("expires_in")
    private Integer expiresIn;

    /**
     * OPTIONAL. The refresh token, which can be used to obtain new access tokens.
     */
    @JsonProperty("refresh_token")
    private String refreshToken;

    /**
     * OPTIONAL. The scope of the access token.
     */
    @JsonProperty("scope")
    private String scope;

    /**
     * OPTIONAL. String containing a nonce to be used to create a proof of possession of key material when requesting a Credential.
     */
    @JsonProperty("c_nonce")
    private String cNonce;

    /**
     * OPTIONAL. Lifetime in seconds of the c_nonce.
     */
    @JsonProperty("c_nonce_expires_in")
    private Integer cNonceExpiresIn;

    /**
     * OPTIONAL. JSON array containing authorization details for the issued access token.
     */
    @JsonProperty("authorization_details")
    private Object authorizationDetails;
}
