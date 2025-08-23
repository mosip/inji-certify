/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * OpenID4VP (Verifiable Presentation) Request DTO
 * Used within IAR response to define presentation requirements
 */
@Data
@NoArgsConstructor
public class OpenId4VpRequest {

    /**
     * Response type for VP request - typically "vp_token"
     */
    @JsonProperty("response_type")
    private String responseType;

    /**
     * Response mode for VP request - typically "iar-post.jwt"
     */
    @JsonProperty("response_mode")
    private String responseMode;

    /**
     * Client identifier
     */
    @JsonProperty("client_id")
    private String clientId;

    /**
     * Presentation definition describing required credentials
     */
    @JsonProperty("presentation_definition")
    private PresentationDefinition presentationDefinition;

    /**
     * Cryptographic nonce for security
     */
    @JsonProperty("nonce")
    private String nonce;

    /**
     * State parameter for maintaining request/response correlation
     */
    @JsonProperty("state")
    private String state;
}
