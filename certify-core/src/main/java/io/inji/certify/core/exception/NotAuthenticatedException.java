/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.inji.certify.core.exception;

import io.inji.certify.core.constants.ErrorConstants;

public class NotAuthenticatedException extends CertifyException {

    public NotAuthenticatedException() {
        super(ErrorConstants.INVALID_AUTH_TOKEN);
    }

    public NotAuthenticatedException(String errorCode) {
        super(errorCode);
    }
}
