/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.constants.IarConstants;
import io.mosip.certify.core.dto.IarRequest;
import io.mosip.certify.core.dto.IarResponse;
import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.IarService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

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
    public IarResponse processInteractiveAuthorizationRequest(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "interaction_types_supported", required = false) String interactionTypesSupported,
            @RequestParam(value = "redirect_to_web", required = false) String redirectToWeb,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state) 
            throws CertifyException {
        
        log.info("Processing Interactive Authorization Request for client_id: {}", clientId);
        log.debug("IAR Request details - response_type: {}, code_challenge_method: {}, interaction_types: {}", 
                  responseType, codeChallengeMethod, interactionTypesSupported);

        // Create IarRequest object from form parameters
        IarRequest iarRequest = new IarRequest();
        iarRequest.setResponseType(responseType);
        iarRequest.setClientId(clientId);
        iarRequest.setCodeChallenge(codeChallenge);
        iarRequest.setCodeChallengeMethod(codeChallengeMethod);
        iarRequest.setRedirectUri(redirectUri);
        iarRequest.setInteractionTypesSupported(interactionTypesSupported);
        iarRequest.setRedirectToWeb(redirectToWeb);
        iarRequest.setScope(scope);
        iarRequest.setState(state);

        try {
            // Validate the IAR request
            iarService.validateIarRequest(iarRequest);

            // Process the authorization request
            IarResponse response = iarService.processAuthorizationRequest(iarRequest);

            log.info("IAR processed successfully - status: {}, auth_session: {}", 
                     response.getStatus(), response.getAuthSession());

            return response;

        } catch (CertifyException e) {
            log.error("Failed to process IAR for client_id: {}, error: {}", 
                      clientId, e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error processing IAR for client_id: {}", 
                      clientId, e);
            throw new CertifyException(IarConstants.INVALID_REQUEST, "IAR processing failed", e);
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
