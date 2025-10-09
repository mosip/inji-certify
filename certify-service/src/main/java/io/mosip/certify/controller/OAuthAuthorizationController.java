/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.dto.IarResponse;
import io.mosip.certify.core.dto.IarPresentationResponse;
import io.mosip.certify.core.dto.OAuthTokenRequest;
import io.mosip.certify.core.dto.OAuthTokenResponse;
import io.mosip.certify.core.dto.OAuthTokenError;
import io.mosip.certify.core.dto.IarRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.IarService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

/**
 * OAuth Authorization Controller
 * Handles OAuth 2.0 authorization flows including Interactive Authorization Request (IAR)
 */
@Slf4j
@RestController
@RequestMapping("/oauth")
public class OAuthAuthorizationController {

    @Autowired
    private IarService iarService;

    /**
     * Interactive Authorization Request (IAR) endpoint
     * POST /oauth/iar
     * 
     * Handles both initial authorization requests and VP presentation responses.
     * Determines the request type based on the presence of auth_session and openid4vp_presentation.
     * 
     * For initial requests: Returns IarResponse containing status, auth_session, and openid4vp_request if interaction required
     * For VP presentations: Returns IarPresentationResponse containing authorization code or error
     * 
     * @param iarRequest Form parameters containing either authorization request fields or VP presentation fields
     * @return ResponseEntity with IarResponse or IarPresentationResponse
     * @throws CertifyException if request processing fails
     */
    @PostMapping(value = "/iar",
             consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
             produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> handleIarRequest(@Valid @ModelAttribute IarRequest iarRequest)
        throws CertifyException {

        log.info("Received IAR request");

        Object response = iarService.handleIarRequest(iarRequest);

        if (response instanceof IarPresentationResponse presentationResponse) {
            if (IarStatus.OK.equals(presentationResponse.getStatus())) {
                return ResponseEntity.ok(presentationResponse);
            }
            return ResponseEntity.badRequest().body(presentationResponse);
        } else if (response instanceof IarResponse) {
            return ResponseEntity.ok(response);
        } else {
            log.error("Unexpected response type from service: {}",
                    response != null ? response.getClass().getSimpleName() : "null");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
        }
    }


    /**
     * OAuth Token endpoint (Step 19-20)
     * POST /oauth/token
     * 
     * Exchanges authorization code for access token and c_nonce.
     * Supports authorization_code grant type for IAR flow.
     * 
     * @param tokenRequest OAuth token request containing grant_type, code, redirect_uri, client_id, code_verifier
     * @return ResponseEntity with OAuthTokenResponse containing access_token and c_nonce
     * @throws CertifyException if token request processing fails
     */
    @PostMapping(value = "/token",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> processTokenRequest(@Valid OAuthTokenRequest tokenRequest)
            throws CertifyException {
        log.info("Processing OAuth token request for grant_type: {}", tokenRequest.getGrantType());

        try {
            // Process the token request
            OAuthTokenResponse response = iarService.processTokenRequest(tokenRequest);

            log.info("Token issued successfully");

            return ResponseEntity.ok(response);

        } catch (CertifyException e) {
            log.error("Failed to process token request, error: {}",
                      e.getMessage(), e);
            
            // Return OAuth error response
            OAuthTokenError errorResponse = new OAuthTokenError(e.getErrorCode(), e.getMessage());
            
            return ResponseEntity.badRequest().body(errorResponse);
        } catch (Exception e) {
            log.error("Unexpected error processing token request", e);
            
            OAuthTokenError errorResponse = new OAuthTokenError("server_error", "Internal server error");
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

}
