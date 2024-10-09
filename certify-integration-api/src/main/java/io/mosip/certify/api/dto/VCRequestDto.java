/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.api.dto;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class VCRequestDto {
    private List<String> context; //holds @context values
    private List<String> type;
    private String format;
    private Map<String, Object> credentialSubject;
    private String doctype;
    private Map<String, Object> claims;
}
