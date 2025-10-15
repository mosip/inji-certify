/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.IarRequest;
import io.mosip.certify.core.dto.OAuthTokenRequest;
import io.mosip.certify.core.dto.OAuthTokenResponse;
import io.mosip.certify.core.exception.CertifyException;

/**
 * Interactive Authorization Request (IAR) Service Interface
 * Handles authorization requests for OpenID4VCI credential issuance
 */
public interface IarService {


    /**
     * Handle unified IAR request
     * Determines whether this is an initial authorization request or VP presentation response
     * and routes to the appropriate processing method
     * 
     * @param unifiedRequest The unified request containing either authorization or presentation data
     * @return Object containing either IarResponse or IarAuthorizationResponse
     * @throws CertifyException if request processing fails
     */
    Object handleIarRequest(IarRequest unifiedRequest) throws CertifyException;

    /**
     * Process OAuth Token Request (Step 19-20)
     * Exchanges authorization code for access token and c_nonce
     * 
     * @param tokenRequest The token request containing authorization code
     * @return OAuthTokenResponse with access_token and c_nonce
     * @throws CertifyException if token request processing fails
     */
    OAuthTokenResponse processTokenRequest(OAuthTokenRequest tokenRequest) throws CertifyException;
}
