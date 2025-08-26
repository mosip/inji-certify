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
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> processIarRequest(@RequestParam Map<String, String> params)
            throws CertifyException {
        log.info("Processing IAR request with parameters: {}", params.keySet());

        // Determine which type of request this is based on parameters
        if (params.containsKey("auth_session") && params.containsKey("openid4vp_presentation")) {
            // Step 13-18: Handle VP presentation response
            return processVpPresentationResponse(params);
        } else {
            // Step 5-9: Handle initial IAR request
            return processInitialIarRequest(params);
        }
    }

    /**
     * Process initial IAR request (Steps 5-9)
     *
     * @param params Form parameters containing response_type, client_id, etc.
     * @return ResponseEntity with IarResponse containing status, auth_session, and openid4vp_request
     * @throws CertifyException if request processing fails
     */
    private ResponseEntity<?> processInitialIarRequest(Map<String, String> params)
            throws CertifyException {
        log.info("Processing initial IAR request for client_id: {}", params.get("client_id"));
        log.debug("IAR Request details - response_type: {}, code_challenge_method: {}, interaction_types: {}",
                  params.get("response_type"), params.get("code_challenge_method"),
                  params.get("interaction_types_supported"));

        // Create IarRequest from params
        IarRequest iarRequest = new IarRequest();
        iarRequest.setResponseType(params.get("response_type"));
        iarRequest.setClientId(params.get("client_id"));
        iarRequest.setCodeChallenge(params.get("code_challenge"));
        iarRequest.setCodeChallengeMethod(params.get("code_challenge_method"));
        iarRequest.setRedirectUri(params.get("redirect_uri"));
        iarRequest.setInteractionTypesSupported(params.get("interaction_types_supported"));
        iarRequest.setRedirectToWeb(params.get("redirect_to_web"));

        try {
            // Validate the IAR request
            iarService.validateIarRequest(iarRequest);

            // Process the authorization request
            IarResponse response = iarService.processAuthorizationRequest(iarRequest);

            log.info("IAR processed successfully - status: {}, auth_session: {}",
                     response.getStatus(), response.getAuthSession());

            return ResponseEntity.ok(response);

        } catch (CertifyException e) {
            log.error("Failed to process IAR for client_id: {}, error: {}",
                      params.get("client_id"), e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error processing IAR for client_id: {}",
                      params.get("client_id"), e);
            throw new CertifyException(IarConstants.INVALID_REQUEST, "IAR processing failed", e);
        }
    }

    /**
     * Process VP presentation response (Steps 13-18)
     *
     * @param params Form parameters containing auth_session and openid4vp_presentation
     * @return ResponseEntity with IarPresentationResponse containing status and authorization_code
     * @throws CertifyException if VP processing fails
     */
    private ResponseEntity<?> processVpPresentationResponse(Map<String, String> params)
            throws CertifyException {
        String authSession = params.get("auth_session");
        String presentation = params.get("openid4vp_presentation");

        log.info("Processing VP presentation response for auth_session: {}", authSession);
        log.debug("VP presentation: {}", presentation);

        // Create IarPresentationRequest DTO
        IarPresentationRequest presentationRequest = new IarPresentationRequest();
        presentationRequest.setAuthSession(authSession);
        presentationRequest.setOpenid4vpPresentation(presentation);

        try {
            // Process the presentation through service layer
            IarPresentationResponse response = iarService.processVpPresentationResponse(presentationRequest);

            log.info("VP presentation processed - status: {}", response.getStatus());

            // Return appropriate response based on VP verification result
            if ("ok".equals(response.getStatus())) {
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.badRequest().body(response);
            }

        } catch (CertifyException e) {
            log.error("Failed to process VP presentation for auth_session: {}, error: {}",
                      authSession, e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error processing VP presentation for auth_session: {}",
                      authSession, e);
            throw new CertifyException(IarConstants.INVALID_REQUEST, "VP presentation processing failed", e);
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
