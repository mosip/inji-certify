/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Interactive Authorization Presentation Response DTO for OpenID4VCI
 * Response from POST /iar endpoint for Verifiable Presentation submission
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IarPresentationResponse {

    /**
     * Status of the presentation response
     * - "ok": VP verification successful
     * - "error": VP verification failed
     */
    @JsonProperty("status")
    private String status;

    /**
     * OAuth 2.0 authorization code (if status is "ok")
     */
    @JsonProperty("authorization_code")
    private String authorizationCode;

    /**
     * Error code (if status is "error")
     */
    @JsonProperty("error")
    private String error;

    /**
     * Error description (if status is "error")
     */
    @JsonProperty("error_description")
    private String errorDescription;
}