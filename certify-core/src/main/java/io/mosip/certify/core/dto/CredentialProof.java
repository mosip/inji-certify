/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.ErrorConstants;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
public class CredentialProof {

    /**
     * The proof object MUST contain a proof_type claim of type JSON string denoting the concrete proof type.
     */
    @NotBlank(message = ErrorConstants.UNSUPPORTED_PROOF_TYPE)
    private String proof_type;

    /**
     * When proof_type is jwt, a proof object MUST include a jwt claim
     */
    private String jwt;

    /**
     * When proof_type is cwt, a proof object MUST include a cwt claim
     */
    private String cwt;
}
