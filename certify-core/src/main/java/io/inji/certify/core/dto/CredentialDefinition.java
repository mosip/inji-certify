/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.inji.certify.core.dto;


import com.fasterxml.jackson.annotation.JsonProperty;
import io.inji.certify.core.constants.ErrorConstants;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;

@Data
public class CredentialDefinition {

    @JsonProperty("@context")
    private List<@NotBlank(message = ErrorConstants.INVALID_REQUEST) String> context;

    @NotEmpty(message = ErrorConstants.INVALID_REQUEST)
    private List<@NotBlank(message = ErrorConstants.INVALID_REQUEST) String> type;

    private Map<String, Object> credentialSubject;

}
