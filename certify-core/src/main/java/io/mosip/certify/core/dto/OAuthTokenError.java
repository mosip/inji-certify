/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

public class OAuthTokenError extends ErrorResponse {
    
    public OAuthTokenError() {
        super();
    }
    
    public OAuthTokenError(String error, String errorDescription) {
        super();
        setError(error);
        setErrorDescription(errorDescription);
    }
}
