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
 * Response DTO from Verify Service VP Request endpoint
 * Contains the generated VP request details
 */
@Data
@NoArgsConstructor
public class VerifyVpResponse {

    @JsonProperty("transactionId")
    private String transactionId;

    @JsonProperty("requestId")
    private String requestId;

    @JsonProperty("authorizationDetails")
    private AuthorizationDetails authorizationDetails;

    @JsonProperty("expiresAt")
    private Long expiresAt;

    @Data
    @NoArgsConstructor
    public static class AuthorizationDetails {
        @JsonProperty("clientId")
        private String clientId;

        @JsonProperty("presentationDefinition")
        private PresentationDefinition presentationDefinition;

        @JsonProperty("nonce")
        private String nonce;

        @JsonProperty("responseUri")
        private String responseUri;

        @JsonProperty("responseType")
        private String responseType;

        @JsonProperty("responseMode")
        private String responseMode;

        @JsonProperty("issuedAt")
        private Long issuedAt;
    }
}
