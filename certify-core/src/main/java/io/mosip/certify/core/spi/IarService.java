/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.IarPresentationRequest;
import io.mosip.certify.core.dto.IarPresentationResponse;
import io.mosip.certify.core.dto.IarRequest;
import io.mosip.certify.core.dto.IarResponse;
import io.mosip.certify.core.dto.OAuthTokenRequest;
import io.mosip.certify.core.dto.OAuthTokenResponse;
import io.mosip.certify.core.dto.UnifiedIarRequest;
import io.mosip.certify.core.exception.CertifyException;

/**
 * Interactive Authorization Request (IAR) Service Interface
 * Handles authorization requests for OpenID4VCI credential issuance
 */
public interface IarService {

    /**
     * Process Interactive Authorization Request
     * Determines if presentation is needed and returns appropriate response
     * 
     * @param iarRequest The authorization request details
     * @return IarResponse containing status, type, auth session and openid4vp request
     * @throws CertifyException if request processing fails
     */
    IarResponse processAuthorizationRequest(IarRequest iarRequest) throws CertifyException;

    /**
     * Generate auth session identifier
     * Creates a unique session ID for tracking the authorization flow
     * 
     * @return String session identifier
     */
    String generateAuthSession();

    /**
     * Validate IAR request parameters
     * Checks if the request contains all required parameters and valid values
     * 
     * @param iarRequest The authorization request to validate
     * @throws CertifyException if validation fails
     */
    void validateIarRequest(IarRequest iarRequest) throws CertifyException;

    /**
     * Generate OpenID4VP request
     * Creates presentation definition and OpenID4VP request details
     * Initially hardcoded, later to be replaced with verify service integration
     * 
     * @param iarRequest The original authorization request
     * @param authSession The generated auth session ID
     * @return IarResponse with OpenID4VP request details
     * @throws CertifyException if generation fails
     */
    IarResponse generateOpenId4VpRequest(IarRequest iarRequest, String authSession) throws CertifyException;

    IarPresentationResponse processVpPresentationResponse(IarPresentationRequest presentationRequest) throws CertifyException;

    /**
     * Handle unified IAR request
     * Determines whether this is an initial authorization request or VP presentation response
     * and routes to the appropriate processing method
     * 
     * @param unifiedRequest The unified request containing either authorization or presentation data
     * @return Object containing either IarResponse or IarPresentationResponse
     * @throws CertifyException if request processing fails
     */
    Object handleIarRequest(UnifiedIarRequest unifiedRequest) throws CertifyException;

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
