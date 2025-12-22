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
 * Presentation Definition DTO for OpenID4VP
 * Defines requirements for verifiable presentation
 */
@Data
@NoArgsConstructor
public class PresentationDefinition {

    /**
     * Unique identifier for this presentation definition
     */
    @JsonProperty("id")
    private String id;

    /**
     * Human-readable name for this presentation definition
     */
    @JsonProperty("name")
    private String name;

    /**
     * Human-readable purpose for this presentation definition
     */
    @JsonProperty("purpose")
    private String purpose;

    /**
     * Array of input descriptors defining credential requirements
     */
    @JsonProperty("input_descriptors")
    private List<InputDescriptor> inputDescriptors;
}
