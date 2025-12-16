/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.dto.IarResponse;
import io.mosip.certify.core.dto.IarAuthorizationResponse;
import io.mosip.certify.core.dto.OAuthTokenRequest;
import io.mosip.certify.core.dto.OAuthTokenResponse;
import io.mosip.certify.core.dto.OAuthTokenError;
import io.mosip.certify.core.dto.IarRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.IarService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.services.KeyManagerConstants;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

/**
 * OAuth Authorization Controller
 * Handles OAuth 2.0 authorization flows including Interactive Authorization Request (IAR)
 */
@Slf4j
@RestController
@RequestMapping("/oauth")
public class OAuthController {

    @Autowired
    private IarService iarService;

    @Autowired
    private JwksService jwksService;

    /**
     * Interactive Authorization Request (IAR) endpoint
     * POST /oauth/iar
     * 
     * Handles both initial authorization requests and VP presentation responses.
     * Determines the request type based on the presence of auth_session and openid4vp_presentation.
     * 
     * For initial requests: Returns IarResponse containing status, auth_session, and openid4vp_request if interaction required
     * For VP presentations: Returns IarAuthorizationResponse containing authorization code or error
     * 
     * @param iarRequest Form parameters containing either authorization request fields or VP presentation fields
     * @return ResponseEntity with IarResponse or IarAuthorizationResponse
     * @throws CertifyException if request processing fails
     */
    @PostMapping(value = "/iar",
             consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
             produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> handleIarRequest(@Valid @ModelAttribute IarRequest iarRequest)
        throws CertifyException {

        log.info("Received IAR request");

        Object response = iarService.handleIarRequest(iarRequest);

        if (response instanceof IarAuthorizationResponse presentationResponse) {
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

    /**
     * Get JWK set endpoint for OAuth access token verification
     * 
     * Cached for 5 minutes to improve performance and reduce load on keymanager service.
     * Returns empty keys array if no valid certificates are found (standard OAuth behavior).
     * Only successful responses (200 OK) are cached - errors are not cached to allow retries.
     * 
     * @return ResponseEntity with JWK set containing public keys
     */
    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwks() {
        log.info("Fetching JWK set for CERTIFY_SERVICE_APP_ID");
        
        try {
            Map<String, Object> response = jwksService.getJwks();
            
            if (response != null && response.containsKey("keys")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> jwkList = (List<Map<String, Object>>) response.get("keys");
                if (jwkList != null && !jwkList.isEmpty()) {
                    log.info("JWK set retrieved successfully with {} keys", jwkList.size());
                    return ResponseEntity.ok(response);
                } else {
                    log.warn("JWK set is empty - no valid certificates available. This may cause token validation failures.");
                    // Return empty keys array per OAuth 2.0 spec
                    return ResponseEntity.ok(response);
                }
            } else {
                log.error("Invalid response structure from getJwksInternal");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("keys", Collections.emptyList());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
            }
            
        } catch (Exception e) {
            log.error("Failed to retrieve JWK set from keymanager service", e);
            // Return empty keys array per OAuth 2.0 spec - clients should handle this gracefully
            // Do NOT cache error responses - allow retries
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("keys", Collections.emptyList());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
        }
    }
}

