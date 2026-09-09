/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.IarStatus;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Interactive Authorization Response DTO for OpenID4VCI
 * Response from POST /iae endpoint for Verifiable Presentation submission
 */
@Data
@NoArgsConstructor
public class IarAuthorizationResponse extends IarResponse{

    /**
     * OAuth 2.0 authorization code (if status is "ok")
     */
    @JsonProperty("code")
    private String code;

}