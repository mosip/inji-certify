/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Valid;
import lombok.Data;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.Map;

@Data
public class CredentialRequest {

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

    /**
     * "format": jwt_vc_json | jwt_vc_json-ld | ldp_vc
     * REQUIRED
     * JSON object containing (and isolating) the detailed description of the credential type.
     * This object MUST be processed using full JSON-LD processing.
     * It consists of the following sub claims:
     * @context: REQUIRED. JSON array
     * types: REQUIRED. JSON array. This claim contains the type values the Wallet shall request
     * in the subsequent Credential Request.
     */
    @Valid
    private CredentialDefinition credential_definition;

    private String doctype;

    /**
     * The claims that are asserted in this credential.
     */
    private Map<String,Object> claims;

    String vct;
}
