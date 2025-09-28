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
 * VP Verification Response DTO from VP Verifier service
 * Response from POST /vp-submission/direct-post endpoint
 */
@Data
@NoArgsConstructor
public class VpVerificationResponse {

    /**
     * Verification status - typically "ok" for success or "error" for failure
     */
    @JsonProperty("status")
    private String status;

    /**
     * Error code if verification failed
     */
    @JsonProperty("error")
    private String error;

    /**
     * Error description if verification failed
     */
    @JsonProperty("error_description")
    private String errorDescription;

    /**
     * Request ID that was verified
     */
    @JsonProperty("request_id")
    private String requestId;

    /**
     * Transaction ID related to the verification
     */
    @JsonProperty("transaction_id")
    private String transactionId;

    /**
     * Additional verification details or claims extracted
     */
    @JsonProperty("verification_details")
    private Object verificationDetails;
}
