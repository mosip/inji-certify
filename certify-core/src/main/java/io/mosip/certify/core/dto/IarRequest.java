/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

/**
 * Interactive Authorization Request (IAR) DTO for OpenID4VCI
 * Used for POST /iar endpoint to initiate authorization flow
 */
@Data
@NoArgsConstructor
public class IarRequest {

    /**
     * OAuth 2.0 Response Type - typically "code"
     */
    @NotBlank(message = "response_type is required")
    @JsonProperty("response_type")
    private String responseType;

    /**
     * OAuth 2.0 Client Identifier
     */
    @NotBlank(message = "client_id is required")
    @JsonProperty("client_id")
    private String clientId;

    /**
     * PKCE Code Challenge
     */
    @NotBlank(message = "code_challenge is required")
    @JsonProperty("code_challenge")
    private String codeChallenge;

    /**
     * PKCE Code Challenge Method - typically "S256"
     */
    @NotBlank(message = "code_challenge_method is required")
    @JsonProperty("code_challenge_method")
    private String codeChallengeMethod;

    /**
     * OAuth 2.0 Redirect URI
     */
    @NotBlank(message = "redirect_uri is required")
    @JsonProperty("redirect_uri")
    private String redirectUri;

    /**
     * Supported interaction types - e.g., "openid4vp_presentation"
     */
    @JsonProperty("interaction_types_supported")
    private String interactionTypesSupported;

    /**
     * Whether to redirect to web interface
     */
    @JsonProperty("redirect_to_web")
    private String redirectToWeb;

    /**
     * OAuth 2.0 Scope parameter - specifies the credential types being requested
     */
    @JsonProperty("scope")
    private String scope;

}
