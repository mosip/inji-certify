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
 * Input Descriptor DTO for Presentation Definition
 * Describes credential requirements and constraints
 */
@Data
@NoArgsConstructor
public class InputDescriptor {

    /**
     * Unique identifier for this input descriptor
     */
    @JsonProperty("id")
    private String id;

    /**
     * Human-readable name for this input descriptor
     */
    @JsonProperty("name")
    private String name;

    /**
     * Human-readable purpose for this input descriptor
     */
    @JsonProperty("purpose")
    private String purpose;

    /**
     * Constraints that must be satisfied for this input
     */
    @JsonProperty("constraints")
    private InputConstraints constraints;
}
