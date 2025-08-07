/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * OAuth 2.0 Authorization Server Metadata DTO as per RFC 8414
 * Note: authorization_endpoint is not included as this implementation
 * uses browser-less flows via authorization_challenge_endpoint.
 */
@Data
@NoArgsConstructor
public class OAuthASMetadataDTO {

    /**
     * The authorization server's issuer identifier
     */
    @JsonProperty("issuer")
    private String issuer;

    /**
     * URL of the authorization server's token endpoint
     */
    @JsonProperty("token_endpoint")
    private String tokenEndpoint;

    /**
     * URL of the authorization server's JWK Set document
     */
    @JsonProperty("jwks_uri")
    private String jwksUri;

    /**
     * JSON array containing a list of the OAuth 2.0 grant type values that this authorization server supports
     */
    @JsonProperty("grant_types_supported")
    private List<String> grantTypesSupported;

    /**
     * JSON array containing a list of the OAuth 2.0 response type values that this authorization server supports
     */
    @JsonProperty("response_types_supported")
    private List<String> responseTypesSupported;

    /**
     * JSON array containing a list of client authentication methods supported by this token endpoint
     */
    @JsonProperty("token_endpoint_auth_methods_supported")
    private List<String> tokenEndpointAuthMethodsSupported;

    /**
     * URL of the authorization server's introspection endpoint
     */
    @JsonProperty("introspection_endpoint")
    private String introspectionEndpoint;

    /**
     * OAuth 2.0 for First-Party Apps endpoint - used for browser-less flows
     */
    @JsonProperty("authorization_challenge_endpoint")
    private String authorizationChallengeEndpoint;
}
