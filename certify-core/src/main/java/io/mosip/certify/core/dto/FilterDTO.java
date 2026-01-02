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
 * Filter DTO for Field Constraints
 * Defines filtering criteria for credential field values
 */
@Data
@NoArgsConstructor
public class FilterDTO {

    /**
     * Type of filter to apply (e.g., regex, exact match)
     */
    @JsonProperty("type")
    private String type;

    /**
     * Pattern or value to match against the field
     */
    @JsonProperty("pattern")
    private String pattern;
}
