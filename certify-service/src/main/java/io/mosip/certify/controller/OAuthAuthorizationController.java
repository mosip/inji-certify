/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.constants.IarConstants;
import io.mosip.certify.core.dto.IarRequest;
import io.mosip.certify.core.dto.IarResponse;
import io.mosip.certify.core.dto.IarPresentationRequest;
import io.mosip.certify.core.dto.IarPresentationResponse;
import io.mosip.certify.core.dto.OAuthTokenRequest;
import io.mosip.certify.core.dto.OAuthTokenResponse;
import io.mosip.certify.core.dto.OAuthTokenError;
import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.IarService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

import java.util.Locale;

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

    @Autowired
    private MessageSource messageSource;

    /**
     * Interactive Authorization Request (IAR) endpoint
     * POST /oauth/iar
     * 
     * Handles authorization requests from wallets to determine if interaction is required
     * for credential issuance. Returns OpenID4VP presentation requirements if needed.
     * 
     * @param iarRequest The authorization request containing client_id, code_challenge, etc.
     * @return IarResponse containing status, auth_session, and openid4vp_request if interaction required
     * @throws CertifyException if request processing fails
     */
    
    @PostMapping(value = "/iar",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE,
                 params = {"!auth_session", "!openid4vp_presentation"})
    public ResponseEntity<?> processInitialIarRequest(@RequestParam Map<String, String> params)
            throws CertifyException {
        log.info("Processing initial IAR request for client_id: {}", params.get("client_id"));

        IarRequest iarRequest = new IarRequest();
        iarRequest.setResponseType(params.get("response_type"));
        iarRequest.setClientId(params.get("client_id"));
        iarRequest.setCodeChallenge(params.get("code_challenge"));
        iarRequest.setCodeChallengeMethod(params.get("code_challenge_method"));
        iarRequest.setRedirectUri(params.get("redirect_uri"));
        iarRequest.setInteractionTypesSupported(params.get("interaction_types_supported"));
        iarRequest.setRedirectToWeb(params.get("redirect_to_web"));
        iarRequest.setScope(params.get("scope"));

        IarResponse response = iarService.processAuthorizationRequest(iarRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping(value = "/iar",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE,
                 params = {"auth_session", "openid4vp_presentation"})
    public ResponseEntity<?> processVpPresentationResponse(@RequestParam Map<String, String> params)
            throws CertifyException {
        log.info("Processing VP presentation response for auth_session: {}", params.get("auth_session"));

        IarPresentationRequest presentationRequest = new IarPresentationRequest();
        presentationRequest.setAuthSession(params.get("auth_session"));
        presentationRequest.setOpenid4vpPresentation(params.get("openid4vp_presentation"));

        IarPresentationResponse response = iarService.processVpPresentationResponse(presentationRequest);
        if (IarConstants.STATUS_OK.equals(response.getStatus())) {
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.badRequest().body(response);
    }

    /**
     * OAuth Token endpoint (Step 19-20)
     * POST /oauth/token
     * 
     * Exchanges authorization code for access token and c_nonce.
     * Supports authorization_code grant type for IAR flow.
     * 
     * @param params Form parameters containing grant_type, code, redirect_uri, client_id, code_verifier
     * @return ResponseEntity with OAuthTokenResponse containing access_token and c_nonce
     * @throws CertifyException if token request processing fails
     */
    @PostMapping(value = "/token",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> processTokenRequest(@RequestParam Map<String, String> params)
            throws CertifyException {
        log.info("Processing OAuth token request for grant_type: {}", params.get("grant_type"));

        // Create OAuthTokenRequest from params
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrantType(params.get("grant_type"));
        tokenRequest.setCode(params.get("code"));
        tokenRequest.setRedirectUri(params.get("redirect_uri"));
        tokenRequest.setClientId(params.get("client_id"));
        tokenRequest.setCodeVerifier(params.get("code_verifier"));
        tokenRequest.setClientSecret(params.get("client_secret"));

        try {
            // Process the token request
            OAuthTokenResponse response = iarService.processTokenRequest(tokenRequest);

            log.info("Token issued successfully for client_id: {}", tokenRequest.getClientId());

            return ResponseEntity.ok(response);

        } catch (CertifyException e) {
            log.error("Failed to process token request for client_id: {}, error: {}",
                      tokenRequest.getClientId(), e.getMessage(), e);
            
            // Return OAuth error response
            OAuthTokenError errorResponse = new OAuthTokenError();
            errorResponse.setError(e.getErrorCode());
            errorResponse.setErrorDescription(e.getMessage());
            
            return ResponseEntity.badRequest().body(errorResponse);
        } catch (Exception e) {
            log.error("Unexpected error processing token request for client_id: {}",
                      tokenRequest.getClientId(), e);
            
            OAuthTokenError errorResponse = new OAuthTokenError();
            errorResponse.setError("server_error");
            errorResponse.setErrorDescription("Internal server error");
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Exception handler for IAR-related CertifyExceptions
     * Returns structured error response following OAuth 2.0 error format
     */
    @ResponseBody
    @ExceptionHandler(CertifyException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public VCError iarExceptionHandler(CertifyException ex) {
        VCError vcError = new VCError();
        vcError.setError(ex.getErrorCode());
        vcError.setError_description(messageSource.getMessage(ex.getErrorCode(), null, ex.getErrorCode(), Locale.getDefault()));
        
        log.error("IAR processing error - code: {}, description: {}", ex.getErrorCode(), vcError.getError_description());
        
        return vcError;
    }
}
