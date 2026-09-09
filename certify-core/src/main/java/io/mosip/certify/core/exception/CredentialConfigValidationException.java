/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.exception;

import io.mosip.certify.core.dto.Error;

import java.util.Collections;
import java.util.List;

/**
 * Carries every validation failure found while validating a credential configuration
 * request, so an issuer can correct the whole payload in a single pass instead of
 * resubmitting once per error.
 */
public class CredentialConfigValidationException extends CertifyException {

    private final List<Error> errors;

    public CredentialConfigValidationException(List<Error> errors) {
        super(errors.getFirst().getErrorCode(), errors.getFirst().getErrorMessage());
        this.errors = Collections.unmodifiableList(errors);
    }

    public List<Error> getErrors() {
        return errors;
    }
}
