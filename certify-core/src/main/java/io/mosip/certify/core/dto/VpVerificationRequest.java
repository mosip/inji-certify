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
 * VP Verification Request DTO for VP Verifier service
 * Used for POST /vp-submission/direct-post endpoint
 */
@Data
@NoArgsConstructor
public class VpVerificationRequest {

    /**
     * The Verifiable Presentation token (required, not blank)
     */
    @NotBlank(message = "vp_token is required")
    @JsonProperty("vp_token")
    private String vpToken;

    /**
     * JSON string containing presentation submission details (required, not blank)
     */
    @NotBlank(message = "presentation_submission is required")
    @JsonProperty("presentation_submission")
    private String presentationSubmission;

    /**
     * The state parameter containing the request ID (required, not blank)
     */
    @NotBlank(message = "state is required")
    @JsonProperty("state")
    private String state;
}
