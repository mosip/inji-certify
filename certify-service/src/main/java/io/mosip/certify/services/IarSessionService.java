/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.AuthorizationDetail;
import io.mosip.certify.core.dto.InteractiveAuthorizationRequest;
import io.mosip.certify.core.dto.VerifyVpResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IarSessionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Service for managing IAR sessions
 * Handles session creation, validation, and management
 */
@Slf4j
@Service
public class IarSessionService {

    @Autowired
    private IarSessionRepository iarSessionRepository;

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

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
        
        // Extract and set scope from authorization_details
        String scope = extractScopeFromAuthorizationDetails(iarRequest);
        iarSession.setScope(scope);
        
        return iarSession;
    }

    /**
     * Extract scope from authorization_details by looking up credential configuration
     * 
     * @param iarRequest The IAR request containing authorization_details
     * @return The scope associated with the credential configuration
     * @throws CertifyException if authorization_details are invalid or credential config not found
     */
    private String extractScopeFromAuthorizationDetails(InteractiveAuthorizationRequest iarRequest) 
            throws CertifyException {
        // Validate authorization_details are present
        List<AuthorizationDetail> authorizationDetails = iarRequest.getAuthorizationDetails();
        if (authorizationDetails == null || authorizationDetails.isEmpty()) {
            log.error("Authorization details are missing in IAR request");
            throw new CertifyException("invalid_request", 
                "authorization_details are required for credential issuance");
        }

        // Get first authorization detail (following existing pattern)
        AuthorizationDetail authDetail = authorizationDetails.get(0);
        String credentialConfigId = authDetail.getCredentialConfigurationId();
        
        if (!StringUtils.hasText(credentialConfigId)) {
            log.error("credential_configuration_id is missing in authorization_details");
            throw new CertifyException("invalid_request", 
                "credential_configuration_id is required in authorization_details");
        }

        log.debug("Looking up credential configuration for ID: {}", credentialConfigId);

        // Lookup credential configuration in database
        Optional<CredentialConfig> configOptional = 
            credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigId);

        if (configOptional.isEmpty()) {
            log.error("Credential configuration not found for ID: {}", credentialConfigId);
            throw new CertifyException("invalid_request", 
                "Invalid credential_configuration_id: " + credentialConfigId);
        }

        CredentialConfig credentialConfig = configOptional.get();

        // Validate credential configuration is active
        if (!Constants.ACTIVE.equals(credentialConfig.getStatus())) {
            log.error("Credential configuration is not active for ID: {}, status: {}", 
                credentialConfigId, credentialConfig.getStatus());
            throw new CertifyException("invalid_request", 
                "Credential configuration is not active: " + credentialConfigId);
        }

        // Extract and validate scope
        String scope = credentialConfig.getScope();
        if (!StringUtils.hasText(scope)) {
            log.error("Scope is not configured for credential configuration ID: {}", credentialConfigId);
            throw new CertifyException("server_error", 
                "Scope not configured for credential: " + credentialConfigId);
        }

        log.debug("Successfully extracted scope '{}' for credential configuration ID: {}", 
            scope, credentialConfigId);
        
        return scope;
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
