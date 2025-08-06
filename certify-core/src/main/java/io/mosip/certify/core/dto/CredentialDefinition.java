/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;


import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

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
