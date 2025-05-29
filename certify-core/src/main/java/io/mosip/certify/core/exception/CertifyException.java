/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.exception;

import io.mosip.certify.core.constants.ErrorConstants;

public class CertifyException extends RuntimeException {

    private String errorCode;
    // TODO: should we add an optional errorDescription
    //  field to simplify debugging as per spec
    //  https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.3.1.2-3.2

    public CertifyException() {
        super(ErrorConstants.UNKNOWN_ERROR);
        this.errorCode = ErrorConstants.UNKNOWN_ERROR;
    }

    public CertifyException(String errorCode) {
        super(errorCode);
        this.errorCode = errorCode;
    }

    public CertifyException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public CertifyException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
