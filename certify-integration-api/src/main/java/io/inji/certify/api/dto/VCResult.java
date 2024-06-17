/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.inji.certify.api.dto;

import lombok.Data;

@Data
public class VCResult<T> {

    /**
     * Format of credential
     * Eg: ldp_vc
     */
    private String format;

    /**
     *
     */
    private T credential;
}
