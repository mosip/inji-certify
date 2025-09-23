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
 * Field Constraint DTO for Input Constraints
 * Defines specific field requirements in credentials
 */
@Data
@NoArgsConstructor
public class FieldConstraint {

    /**
     * JSON Path expressions pointing to required fields in the credential
     */
    @JsonProperty("path")
    private List<String> path;

    /**
     * Optional filter to constrain field values
     */
    @JsonProperty("filter")
    private Object filter;

    /**
     * Whether this field is required or optional
     */
    @JsonProperty("optional")
    private Boolean optional;
}
