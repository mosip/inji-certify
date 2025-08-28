/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * OAuth 2.0 Token Error Response DTO
 * Returned when token request fails
 * 
 * Based on RFC 6749 specification
 */
@Data
public class OAuthTokenError {

    /**
     * REQUIRED. A single ASCII error code from the following:
     * - invalid_request
     * - invalid_client  
     * - invalid_grant
     * - unauthorized_client
     * - unsupported_grant_type
     * - invalid_scope
     */
    @JsonProperty("error")
    private String error;

    /**
     * OPTIONAL. Human-readable ASCII text providing additional information about the error.
     */
    @JsonProperty("error_description")
    private String errorDescription;
}
