/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;


import lombok.Data;

import java.io.Serializable;

@Data
public class VCIssuanceTransaction implements Serializable {

    private String cNonce;
    private long cNonceIssuedEpoch;
    private int cNonceExpireSeconds;


}
