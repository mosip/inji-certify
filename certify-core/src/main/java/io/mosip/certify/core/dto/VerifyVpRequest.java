/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Request DTO for Verify Service VP Request endpoint
 * Used to request VP generation from verify service
 */
@Data
@NoArgsConstructor
public class VerifyVpRequest {

    /**
     * Client identifier for the verification request
     */
    @JsonProperty("clientId")
    private String clientId;

    /**
     * Presentation definition defining what credentials are required
     */
    @JsonProperty("presentationDefinition")
    private PresentationDefinition presentationDefinition;

    /**
     * Presentation definition ID (alternative to full definition)
     */
    @JsonProperty("presentationDefinitionId")
    private String presentationDefinitionId;

    /**
     * Supported response modes for the VP request
     */
    @JsonProperty("responseModesSupported")
    private List<String> responseModesSupported;

    /**
     * Whether encryption is required for the response
     */
    @JsonProperty("encryptionRequired")
    private Boolean encryptionRequired;

    /**
     * Optional transaction ID to use instead of generating one.
     * If provided, verify service will use this transaction ID.
     * This allows using a CSV user ID as transaction ID for identity lookup.
     */
    @JsonProperty("transactionId")
    private String transactionId;
}

