/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.IarConstants;
import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.IarService;
import io.mosip.certify.services.OAuthAuthorizationServerMetadataService;
import io.mosip.certify.services.PreAuthorizedCodeService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


/**
 * OAuth Authorization Controller
 * Handles OAuth 2.0 authorization flows including Interactive Authorization Request (IAR)
 */
@Slf4j
@RestController
public class OAuthController {

    private final IarService iarService;
    private final OAuthAuthorizationServerMetadataService oAuthAuthorizationServerMetadataService;
    private final PreAuthorizedCodeService preAuthorizedCodeService;

    @Autowired
    public OAuthController(IarService iarService,
                           OAuthAuthorizationServerMetadataService oAuthAuthorizationServerMetadataService,
                           PreAuthorizedCodeService preAuthorizedCodeService) {
        this.iarService = iarService;
        this.oAuthAuthorizationServerMetadataService = oAuthAuthorizationServerMetadataService;
        this.preAuthorizedCodeService = preAuthorizedCodeService;
    }

    @GetMapping(value = "/.well-known/oauth-authorization-server", produces = "application/json")
    public OAuthAuthorizationServerMetadataDTO getOAuthAuthorizationServerMetadata() {
        return oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();
    }

    /**
     * Interactive Authorization Request (IAR) endpoint
     * POST /oauth/iae
     * 
     * Handles both initial authorization requests and VP presentation responses.
     * Determines the request type based on the presence of auth_session and openid4vp_response.
     * 
     * For initial requests: Returns IarResponse containing status, auth_session, and openid4vp_request if interaction required
     * For VP presentations: Returns IarAuthorizationResponse containing authorization code or error
     * 
     * @param iarRequest Form parameters containing either authorization request fields or VP presentation fields
     * @return ResponseEntity with IarResponse or IarAuthorizationResponse
     * @throws CertifyException if request processing fails
     */
    @PostMapping(value = "/oauth/iae",
             consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
             produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IarResponse> handleIarRequest(@Valid @ModelAttribute IarRequest iarRequest)
        throws CertifyException {

        log.info("Received IAR request");

        Object response = iarService.handleIarRequest(iarRequest);

        if (response instanceof IarAuthorizationResponse iarAuthorizationResponse) {
            if (IarStatus.OK.equals(iarAuthorizationResponse.getStatus())) {
                return ResponseEntity.ok(iarAuthorizationResponse);
            }
            return ResponseEntity.badRequest().body(iarAuthorizationResponse);
        } else if (response instanceof IarPresentationResponse presentationResponse) {
            return ResponseEntity.ok(presentationResponse);
        } else {
            log.error("Unexpected response type from service: {}",
                    response != null ? response.getClass().getSimpleName() : "null");
            IarResponse iarResponse = new IarResponse();
            iarResponse.setStatus(IarStatus.ERROR);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(iarResponse);
        }
    }

    /**
     * OAuth Token endpoint (Step 19-20)
     * POST /oauth/token
     * 
     * Exchanges authorization code for access token.
     * Supports authorization_code and pre-authorized_code grant types.
     *
     * @param params OAuth token request containing grant_type and relevant fields
     * @return ResponseEntity with OAuthTokenResponse containing access_token
     * @throws CertifyException if token request processing fails
     */
    @PostMapping(value = "/oauth/token",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OAuthTokenResponse> processTokenRequest(@RequestParam Map<String, String> params)
            throws CertifyException {
        log.info("Received OAuth token request");
        try {
            OAuthTokenResponse response;
            String grantType = params.get("grant_type");
            if (StringUtils.isEmpty(grantType)) {
                throw new CertifyException("invalid_request", "grant_type is required");
            }
            log.info("Processing OAuth token request for grant_type: {}", grantType);

            // Check if this is a pre-authorized code grant
            if (Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE.equals(grantType)) {
                OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
                tokenRequest.setGrant_type(grantType);
                tokenRequest.setPre_authorized_code(params.get("pre-authorized_code"));
                tokenRequest.setTx_code(params.get("tx_code"));
                response = preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);
            } else if (IarConstants.GRANT_TYPE_AUTHORIZATION_CODE.equals(grantType)) {
                if (StringUtils.isBlank(params.get("code"))) {
                    throw new CertifyException("invalid_request", "code is required");
                }
                if (StringUtils.isBlank(params.get("code_verifier"))) {
                    throw new CertifyException("invalid_request", "code_verifier is required");
                }
                // Handle authorization_code grant type via IarService
                OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
                tokenRequest.setGrant_type(grantType);
                tokenRequest.setCode(params.get("code"));
                tokenRequest.setCode_verifier(params.get("code_verifier"));
                response = iarService.processTokenRequest(tokenRequest);
            } else {

                throw new CertifyException("invalid_request", "Unsupported or invalid grant_type");
            }

            log.info("Token issued successfully");

            return ResponseEntity.ok(response);

        } catch (CertifyException e) {
            log.error("Failed to process token request, error: {}",
                      e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error processing token request", e);
            throw e;
        }
    }
}

