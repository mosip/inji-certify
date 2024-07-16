/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Map;

@Data
public class MsoMdocVcCredentialRequest  {

    /**
     * REQUIRED. Format of the Credential to be issued.
     */
    @NotBlank(message = ErrorConstants.INVALID_VC_FORMAT)
    private String format;

    /**
     * OPTIONAL.
     * JSON object containing proof of possession of the key material the issued Credential shall be bound to.
     */
    @Valid
    @NotNull(message = ErrorConstants.INVALID_PROOF)
    private CredentialProof proof;

    @Valid
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private String doc_type;

    @Valid
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private Map<String,Object> claims;

}
