/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.dto.InteractiveAuthorizationRequest;
import io.mosip.certify.core.dto.VerifyVpResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.IarSessionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

/**
 * Service for managing IAR sessions
 * Handles session creation, validation, and management
 */
@Slf4j
@Service
public class IarSessionService {

    @Autowired
    private IarSessionRepository iarSessionRepository;

    private static final String SESSION_PREFIX = "iar_session_";

    /**
     * Generate a new auth session identifier
     */
    public String generateAuthSession() {
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        
        String authSession = SESSION_PREFIX + encoded;
        log.info("Auth session generated");
        return authSession;
    }

    /**
     * Create and populate IarSession with validation
     */
    public IarSession createIarSession(InteractiveAuthorizationRequest iarRequest, VerifyVpResponse verifyResponse, 
                                       String authSession, String transactionId) throws CertifyException {
        IarSession iarSession = new IarSession();
        iarSession.setAuthSession(authSession);
        iarSession.setTransactionId(transactionId);
        iarSession.setRequestId(verifyResponse.getRequestId());
        
        // Validate and set authorization details
        if (verifyResponse.getAuthorizationDetails() == null) {
            throw new CertifyException("unknown_error", "Authorization details are required from verify service");
        }
        
        VerifyVpResponse.AuthorizationDetails authDetails = verifyResponse.getAuthorizationDetails();
        iarSession.setVerifyNonce(authDetails.getNonce());
        iarSession.setResponseUri(authDetails.getResponseUri());
        
        // Validate response_uri is present as it's required for VP response
        if (!StringUtils.hasText(authDetails.getResponseUri())) {
            throw new CertifyException("unknown_error", "Response URI is required for VP response from wallet");
        }
        
        if (verifyResponse.getExpiresAt() != null) {
            iarSession.setExpiresAt(LocalDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(verifyResponse.getExpiresAt()),
                java.time.ZoneOffset.UTC));
        }
        iarSession.setClientId(iarRequest.getClientId());
        iarSession.setCodeChallenge(iarRequest.getCodeChallenge());
        iarSession.setCodeChallengeMethod(iarRequest.getCodeChallengeMethod());
        
        return iarSession;
    }

    /**
     * Validate auth session exists
     */
    public boolean isValidAuthSession(String authSession) {
        return iarSessionRepository.findByAuthSession(authSession).isPresent();
    }

    /**
     * Get session by auth session
     */
    public IarSession getSessionByAuthSession(String authSession) throws CertifyException {
        return iarSessionRepository.findByAuthSession(authSession)
                .orElseThrow(() -> new CertifyException("invalid_request", "Invalid auth_session"));
    }
}
