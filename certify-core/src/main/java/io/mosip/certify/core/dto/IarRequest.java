/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.validation.ValidUnifiedIar;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Interactive Authorization Request DTO for OpenID4VCI
 * Combines fields from both InteractiveAuthorizationRequest and IarPresentationRequest
 * Used for the unified /iar endpoint to handle both initial requests and VP presentation responses
 */
@Data
@NoArgsConstructor
@ValidUnifiedIar
public class IarRequest {

    // Fields from InteractiveAuthorizationRequest (for initial authorization requests)
    
    /**
     * OAuth 2.0 Response Type - typically "code"
     */
    @JsonProperty("response_type")
    private String responseType;

    /**
     * OAuth 2.0 Client Identifier
     */
    @JsonProperty("client_id")
    private String clientId;

    /**
     * PKCE Code Challenge
     */
    @JsonProperty("code_challenge")
    private String codeChallenge;

    /**
     * PKCE Code Challenge Method - typically "S256"
     */
    @JsonProperty("code_challenge_method")
    private String codeChallengeMethod;

    /**
     * OAuth 2.0 Redirect URI
     */
    @JsonProperty("redirect_uri")
    private String redirectUri;

    /**
     * Supported interaction types - e.g., "openid4vp_presentation"
     */
    @JsonProperty("interaction_types_supported")
    private String interactionTypesSupported;


    /**
     * Authorization details as per OpenID4VCI specification
     * Specifies the credential types being requested
     */
    @JsonProperty("authorization_details")
    private List<AuthorizationDetail> authorizationDetails;

    // Fields from IarPresentationRequest (for VP presentation responses)
    
    /**
     * Authorization session identifier from initial IAR response
     */
    @JsonProperty("auth_session")
    private String authSession;

    /**
     * OpenID4VP presentation response (unencrypted or encrypted JWT)
     */
    @JsonProperty("openid4vp_presentation")
    private String openid4vpPresentation;

}
