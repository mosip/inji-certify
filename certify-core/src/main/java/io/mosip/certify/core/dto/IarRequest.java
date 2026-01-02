/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import io.mosip.certify.core.validation.ValidIar;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Interactive Authorization Request DTO for OpenID4VCI
 * Combines fields from both InteractiveAuthorizationRequest and IarAuthorizationRequest
 * Used for the unified /iar endpoint to handle both initial requests and VP presentation responses
 */
@Data
@NoArgsConstructor
@ValidIar
public class IarRequest {

    // Fields from InteractiveAuthorizationRequest (for initial authorization requests)
    
    /**
     * OAuth 2.0 Response Type - typically "code"
     */
    private String response_type;

    /**
     * OAuth 2.0 Client Identifier
     */
    private String client_id;

    /**
     * PKCE Code Challenge
     */
    private String code_challenge;

    /**
     * PKCE Code Challenge Method - typically "S256"
     */
    private String code_challenge_method;

    /**
     * OAuth 2.0 Redirect URI
     */
    private String redirect_uri;

    /**
     * Supported interaction types - e.g., "openid4vp_presentation"
     */
    private String interaction_types_supported;


    /**
     * Authorization details as per OpenID4VCI specification
     * Specifies the credential types being requested
     */
    private List<AuthorizationDetail> authorization_details;

    // Fields from IarAuthorizationRequest (for VP presentation responses)
    
    /**
     * Authorization session identifier from initial IAR response
     */
    private String auth_session;

    /**
     * OpenID4VP presentation response (unencrypted or encrypted JWT)
     */
    private String openid4vp_response;

}
