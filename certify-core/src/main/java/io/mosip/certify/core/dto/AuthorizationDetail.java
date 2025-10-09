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
 * Authorization Detail DTO for OpenID4VCI specification
 * Represents a single authorization detail in the authorization_details array
 */
@Data
@NoArgsConstructor
public class AuthorizationDetail {

    /**
     * Type of authorization detail - typically "openid_credential"
     */
    @JsonProperty("type")
    private String type;

    /**
     * Locations where the credential can be obtained
     */
    @JsonProperty("locations")
    private String[] locations;

    /**
     * Credential configuration identifier
     */
    @JsonProperty("credential_configuration_id")
    private String credentialConfigurationId;

    /**
     * Format of the credential (e.g., "jwt_vc", "ldp_vc", "vc+sd-jwt")
     */
    @JsonProperty("format")
    private String format;

    /**
     * Verifiable Credential Type (VCT) - required when format is present
     * Used for VC+SD-JWT format to specify the credential type
     */
    @JsonProperty("vct")
    private String vct;

}
