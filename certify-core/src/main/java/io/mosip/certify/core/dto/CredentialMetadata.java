/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class CredentialMetadata {

    private String id;
    private String format;
    private String scope;
    // proof_types_supported is a map from v13 & an array before
    private Object proof_types_supported;
    private List<String> types;
    private Map<String, String> background_image;

}
