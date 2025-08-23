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
 * Interactive Authorization Response (IAR) DTO for OpenID4VCI
 * Response from POST /iar endpoint
 */
@Data
@NoArgsConstructor
public class IarResponse {

    /**
     * Status of the authorization request
     * - "require_interaction": Interaction is required (OpenID4VP presentation)
     * - "complete": Authorization is complete, no interaction needed
     */
    @JsonProperty("status")
    private String status;

    /**
     * Type of interaction required
     * - "openid4vp_presentation": OpenID4VP presentation required
     */
    @JsonProperty("type")
    private String type;

    /**
     * Authorization session identifier for tracking the auth flow
     */
    @JsonProperty("auth_session")
    private String authSession;

    /**
     * OpenID4VP request details when interaction is required
     */
    @JsonProperty("openid4vp_request")
    private OpenId4VpRequest openid4vpRequest;
}
