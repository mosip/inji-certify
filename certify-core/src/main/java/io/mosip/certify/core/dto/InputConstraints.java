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
 * Input Constraints DTO for Input Descriptor
 * Defines field-level constraints for credential verification
 */
@Data
@NoArgsConstructor
public class InputConstraints {

    /**
     * Array of field constraints that must be satisfied
     */
    @JsonProperty("fields")
    private List<FieldConstraint> fields;

    /**
     * Limit the credential types that can be used
     */
    @JsonProperty("limit_disclosure")
    private String limitDisclosure;
}
