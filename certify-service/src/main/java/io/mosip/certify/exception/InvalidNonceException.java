/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.exception;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;

public class InvalidNonceException extends CertifyException {

    private String clientNonce;

    private int clientNonceExpireSeconds;

    public InvalidNonceException(String cNonce, int cNonceExpireSeconds) {
        super(ErrorConstants.INVALID_PROOF);
        this.clientNonce = cNonce;
        this.clientNonceExpireSeconds = cNonceExpireSeconds;
    }

    public String getClientNonce() {
        return this.clientNonce;
    }

    public int getClientNonceExpireSeconds() {
        return this.clientNonceExpireSeconds;
    }
}
