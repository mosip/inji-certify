/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.exception;

import io.mosip.certify.core.constants.ErrorConstants;

/**
 * Raised for any failure to validate a DPoP proof (RFC 9449 §4.3).
 *
 * <p>Mirrors eSignet's exception of the same name. The message-carrying
 * constructor is the addition: eSignet's variant carries only the error code, so
 * every DPoP failure reaches the client as a bare {@code invalid_dpop_proof}.
 * Keeping a description here means a wallet developer is told which check failed
 * - the descriptions are written to be safe to return, naming the claim at fault
 * and never echoing key material or token contents.
 */
public class InvalidDpopHeaderException extends CertifyException {

    public InvalidDpopHeaderException() {
        super(ErrorConstants.INVALID_DPOP_PROOF);
    }

    public InvalidDpopHeaderException(String message) {
        super(ErrorConstants.INVALID_DPOP_PROOF, message);
    }
}
