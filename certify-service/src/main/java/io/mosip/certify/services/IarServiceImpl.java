/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IarConstants;
import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.constants.InteractionType;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.IarService;
import jakarta.validation.Validator;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.IarSessionRepository;
import io.mosip.certify.utils.AccessTokenJwtUtil;

/**
 * Interactive Authorization Request (IAR) Service Implementation
 * Handles authorization requests for OpenID4VCI credential issuance
 * 
 * Integrates with verify service for VP request generation and VP verification.
 * Uses real service endpoints for presentation during issuance flow.
 */
@Slf4j
@Service
public class IarServiceImpl implements IarService {

    private final IarSessionRepository iarSessionRepository;

    private final IarPresentationService iarPresentationService;

    private final IarSessionService iarSessionService;

    private final IarVpRequestService iarVpRequestService;

    private final AccessTokenJwtUtil accessTokenJwtUtil;

    private final Validator validator;

    @Value("${mosip.certify.oauth.token.expires-in-seconds:3600}")
    private int tokenExpiresInSeconds;

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpiresInSeconds;

    @Value("${mosip.certify.iar.authorization-code.expires-minutes:10}")
    private int authorizationCodeExpiresMinutes;

    @Value("${mosip.certify.oauth.token.type:Bearer}")
    private String tokenType;

    @Value("${mosip.certify.oauth.issuer:}")
    private String issuer;

    @Value("${mosip.certify.oauth.access-token.audience:}")
    private String audience;

    private static final String AUTH_CODE_PREFIX = "iar_auth_";

    @Autowired
    public IarServiceImpl(IarSessionRepository iarSessionRepository,
                          IarPresentationService iarPresentationService,
                          IarSessionService iarSessionService,
                          IarVpRequestService iarVpRequestService,
                          AccessTokenJwtUtil accessTokenJwtUtil,
                          Validator validator) {
        this.iarSessionRepository = iarSessionRepository;
        this.iarPresentationService = iarPresentationService;
        this.iarSessionService = iarSessionService;
        this.iarVpRequestService = iarVpRequestService;
        this.accessTokenJwtUtil = accessTokenJwtUtil;
        this.validator = validator;
    }

    private IarResponse processAuthorizationRequest(InteractiveAuthorizationRequest iarRequest) throws CertifyException {
        log.info("Processing IAR for client_id: {}, response_type: {}", 
                 iarRequest.getClientId(), iarRequest.getResponseType());

        try {
            // Validate the request
            validateIarRequest(iarRequest);

            // Generate auth session
            String authSession = iarSessionService.generateAuthSession();

            // Always require interaction (no direct authorization path)
            return generateOpenId4VpRequest(iarRequest, authSession);

        } catch (CertifyException e) {
            log.error("IAR processing failed for client: {}, error: {}", 
                      iarRequest.getClientId(), e.getErrorCode(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during IAR processing for client: {}", 
                      iarRequest.getClientId(), e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "IAR processing failed", e);
        }
    }

    @Override
    public Object handleIarRequest(IarRequest iarRequest) throws CertifyException {
        log.info("Handling IAR request");

        boolean hasAuthSession = iarRequest.getAuth_session() != null && !iarRequest.getAuth_session().trim().isEmpty();
        boolean hasVp = iarRequest.getOpenid4vp_response() != null && !iarRequest.getOpenid4vp_response().trim().isEmpty();

        if (hasAuthSession && hasVp) {
            log.info("Processing VP presentation response for auth_session: {}", iarRequest.getAuth_session());
            IarAuthorizationRequest presentationRequest = new IarAuthorizationRequest();
            presentationRequest.setAuthSession(iarRequest.getAuth_session());
            presentationRequest.setOpenid4vpPresentation(iarRequest.getOpenid4vp_response());
            return iarPresentationService.processVpPresentation(presentationRequest);
        }

        if (!hasAuthSession && !hasVp) {
            log.info("Processing initial authorization request for client_id: {}", iarRequest.getClient_id());
            InteractiveAuthorizationRequest iarInitialRequest = createInteractiveAuthorizationRequest(iarRequest);
            return processAuthorizationRequest(iarInitialRequest);
        }
        
        // Invalid state: only one of auth_session or openid4vp_response is present
        log.error("Invalid IAR request - only one of auth_session or openid4vp_response is present. auth_session: {}, hasVp: {}",
                 hasAuthSession, hasVp);
        throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
    }

    private static InteractiveAuthorizationRequest createInteractiveAuthorizationRequest(IarRequest iarRequest) {
        InteractiveAuthorizationRequest iarInitialRequest = new InteractiveAuthorizationRequest();
        iarInitialRequest.setResponseType(iarRequest.getResponse_type());
        iarInitialRequest.setClientId(iarRequest.getClient_id());
        iarInitialRequest.setCodeChallenge(iarRequest.getCode_challenge());
        iarInitialRequest.setCodeChallengeMethod(iarRequest.getCode_challenge_method());
        iarInitialRequest.setInteractionTypesSupported(iarRequest.getInteraction_types_supported());
        iarInitialRequest.setAuthorizationDetails(iarRequest.getAuthorization_details());
        return iarInitialRequest;
    }

    @Override
    public OAuthTokenResponse processTokenRequest(OAuthTokenRequest tokenRequest) throws CertifyException {
        Set<ConstraintViolation<OAuthTokenRequest>> violations =
                validator.validate(tokenRequest);

        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }
        log.info("Processing OAuth token request for grant_type: {}", 
                 tokenRequest.getGrant_type());

        try {
            // Validate grant type
            if (!IarConstants.GRANT_TYPE_AUTHORIZATION_CODE.equals(tokenRequest.getGrant_type())) {
                throw new CertifyException("unsupported_grant_type", 
                                         "Only authorization_code grant type is supported");
            }

            // Validate authorization code and atomically mark as used to prevent race conditions
            IarSession session = validateAndMarkAuthorizationCodeUsed(tokenRequest);

            OAuthTokenResponse response = new OAuthTokenResponse();
            response.setAccessToken(generateAccessToken(session));
            response.setTokenType(tokenType);
            response.setExpiresIn(tokenExpiresInSeconds);
            
            // Set scope from the session
            if (session.getScope() != null && !session.getScope().isEmpty()) {
                response.setScope(session.getScope());
            }

            // Note: refresh_token and authorization_details are optional and not implemented yet
            // They can be added based on specific requirements
            
            log.info("Token generated successfully");
            return response;

        } catch (CertifyException e) {
            log.error("Token request validation failed, error: {}", 
                      e.getErrorCode(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during token processing", e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Token processing failed", e);
        }
    }

    private void validateIarRequest(InteractiveAuthorizationRequest iarRequest) throws CertifyException {
        log.debug("Validating IAR request for client: {}", iarRequest.getClientId());

        // Validate response_type
        if (!IarConstants.RESPONSE_TYPE_CODE.equals(iarRequest.getResponseType())) {
            throw new CertifyException(IarConstants.UNSUPPORTED_RESPONSE_TYPE, 
                                     "Unsupported response_type: " + iarRequest.getResponseType());
        }
        // Validate client_id
        if (!StringUtils.hasText(iarRequest.getClientId())) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "client_id is required");
        }
        // Validate code_challenge
        if (!StringUtils.hasText(iarRequest.getCodeChallenge())) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "code_challenge is required");
        }
        // Validate code_challenge_method
        if (!IarConstants.CODE_CHALLENGE_METHOD_S256.equals(iarRequest.getCodeChallengeMethod())) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "code_challenge_method must be S256");
        }
        // Validate interaction_types_supported
        validateInteractionTypesSupported(iarRequest.getInteractionTypesSupported());
        // Validate authorization_details
        validateAuthorizationDetails(iarRequest);
        log.debug("IAR request validation successful for client: {}",
                  iarRequest.getClientId());
    }

    private void validateInteractionTypesSupported(String interactionTypesSupported) throws CertifyException {
        if (!StringUtils.hasText(interactionTypesSupported)) {
            log.debug("No interaction_types_supported provided - using default");
            return;
        }

        // Validate OpenID4VCI 1.1 interaction type value.
        Arrays.stream(interactionTypesSupported.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .filter(interactionType -> 
                    InteractionType.OPENID4VP_PRESENTATION.getValue().equals(interactionType))
                .findFirst()
                .orElseThrow(() -> new CertifyException(IarConstants.MISSING_INTERACTION_TYPE,
                    "interaction_types_supported in the request is missing the required interaction type '" +
                        InteractionType.OPENID4VP_PRESENTATION.getValue() + "'"));

        log.debug("Interaction types validation successful: {}", interactionTypesSupported);
    }

    private static void validateAuthorizationDetails(InteractiveAuthorizationRequest iarRequest) {
        if (iarRequest.getAuthorizationDetails() == null || iarRequest.getAuthorizationDetails().isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "authorization_details are required");
        }

        iarRequest.getAuthorizationDetails().forEach(authDetail -> {
            String type = authDetail.getType();
            if (!StringUtils.hasText(type)) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "type is required in authorization_details");
            }
            if (!IarConstants.AUTHORIZATION_DETAILS_TYPE.equals(type)) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST, "authorization details type must be openid_credential");
            }
            if (!StringUtils.hasText(authDetail.getCredentialConfigurationId())) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "credential_configuration_id is required in authorization_details");
            }
        });
    }
    private IarResponse generateOpenId4VpRequest(InteractiveAuthorizationRequest iarRequest, String authSession) throws CertifyException {
        log.info("Generating OpenID4VP request for auth_session: {}", authSession);

        try {
            IarPresentationResponse response = new IarPresentationResponse();
            response.setStatus(IarStatus.REQUIRE_INTERACTION);
            response.setType(InteractionType.OPENID4VP_PRESENTATION);
            response.setAuthSession(authSession);

            // Call verify service with CSV transaction ID
            VerifyVpResponse verifyResponse = iarVpRequestService.createVpRequest(iarRequest);

            // Convert verify response to Object (pass-through from Verify service)
            Object openId4VpRequest = iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);
            response.setOpenid4vpRequest(openId4VpRequest);
            
            IarSession iarSession = iarSessionService.createIarSession(iarRequest, verifyResponse, authSession, verifyResponse.getTransactionId());
            
            iarSessionRepository.save(iarSession);
            return response;

        } catch (Exception e) {
            log.error("Failed to generate OpenID4VP request for auth_session: {}", authSession, e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Failed to generate OpenID4VP request", e);
        }
    }

    /**
     * Atomically validate and mark authorization code as used to prevent race conditions
     */
    private IarSession validateAndMarkAuthorizationCodeUsed(OAuthTokenRequest tokenRequest) throws CertifyException {
        log.debug("Atomically validating and marking authorization code as used (code length: {})", 
                  tokenRequest.getCode() != null ? tokenRequest.getCode().length() : 0);

        if (!StringUtils.hasText(tokenRequest.getCode())) {
            throw new CertifyException("invalid_grant", "Invalid authorization code");
        }

        if (!tokenRequest.getCode().startsWith(AUTH_CODE_PREFIX)) {
            throw new CertifyException("invalid_grant", "Invalid authorization code format");
        }

        // Use database-level atomic update to prevent race conditions
        Optional<IarSession> sessionOpt = iarSessionRepository.findByAuthorizationCode(tokenRequest.getCode());
        if (!sessionOpt.isPresent()) {
            throw new CertifyException("invalid_grant", "Authorization code not found");
        }

        IarSession session = sessionOpt.get();

        // Check if already used (double-check after database retrieval)
        if (Boolean.TRUE.equals(session.getIsCodeUsed())) {
            log.warn("Authorization code already used - potential replay attack");
            throw new CertifyException("invalid_grant", "Authorization code already used");
        }

        // Validate expiration
        if (session.getCodeIssuedAt() != null && 
            session.getCodeIssuedAt().isBefore(LocalDateTime.now().minusMinutes(authorizationCodeExpiresMinutes))) {
            throw new CertifyException("invalid_grant", "Authorization code expired");
        }

        // Validate PKCE, redirect_uri, and client_secret
        validatePkceCodeVerifier(tokenRequest, session);

        // ATOMIC UPDATE: Mark code as used in single database operation
        try {
            int updatedRows = iarSessionRepository.markAuthorizationCodeAsUsed(
                tokenRequest.getCode(), 
                LocalDateTime.now()
            );
            
            if (updatedRows == 0) {
                // Another thread already marked this code as used
                log.warn("Authorization code was used by another request - potential race condition prevented");
                throw new CertifyException("invalid_grant", "Authorization code already used");
            }
            
            // Update the session object to reflect the change
            session.setIsCodeUsed(true);
            session.setCodeUsedAt(LocalDateTime.now());
            
            log.debug("Authorization code atomically marked as used");
            return session;
            
        } catch (CertifyException e) {
            throw e;
        }
        catch (Exception e) {
            log.error("Failed to atomically mark authorization code as used", e);
            throw new CertifyException("server_error", "Failed to process authorization code", e);
        }
    }

    private void validatePkceCodeVerifier(OAuthTokenRequest tokenRequest, IarSession session) throws CertifyException {
        String codeVerifier = tokenRequest.getCode_verifier();
        String codeChallenge = session.getCodeChallenge();
        String codeChallengeMethod = session.getCodeChallengeMethod();
        
        log.debug("PKCE validation - codeVerifier length: {}, codeChallenge length: {}, codeChallengeMethod: {}", 
                 codeVerifier != null ? codeVerifier.length() : 0, 
                 codeChallenge != null ? codeChallenge.length() : 0, 
                 codeChallengeMethod);
        
        if (!StringUtils.hasText(codeVerifier)) {
            throw new CertifyException("invalid_request", "code_verifier is required for PKCE");
        }
        
        if (!StringUtils.hasText(codeChallenge) || !StringUtils.hasText(codeChallengeMethod)) {
            log.error("PKCE parameters missing from session - codeChallenge: '{}', codeChallengeMethod: '{}'", 
                     codeChallenge, codeChallengeMethod);
            throw new CertifyException("invalid_request", "PKCE parameters missing from authorization request");
        }
        
        try {
            String computedChallenge;
            if (IarConstants.CODE_CHALLENGE_METHOD_S256.equals(codeChallengeMethod)) {
                java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(codeVerifier.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                computedChallenge = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            } else {
                throw new CertifyException("invalid_request", "Unsupported code_challenge_method: " + codeChallengeMethod);
            }
            
            if (!codeChallenge.equals(computedChallenge)) {
                log.warn("PKCE validation failed - code_challenge mismatch");
                throw new CertifyException("invalid_grant", "Invalid code_verifier");
            }
            
            log.debug("PKCE validation successful");
            
        } catch (java.security.NoSuchAlgorithmException e) {
            log.error("SHA-256 algorithm not available for PKCE validation", e);
            throw new CertifyException("server_error", "PKCE validation failed");
        }
    }
    
    /**
     * Generate a signed JWT access token using the provided session data
     * 
     * @param session The IAR session containing client and transaction information
     * @return Signed JWT access token string
     */
    private String generateAccessToken(IarSession session) {
        try {
            String jwtToken = accessTokenJwtUtil.generateSignedJwt(
                session, 
                issuer,
                audience,
                tokenExpiresInSeconds
            );
            log.debug("Generated JWT access token for client_id: {}, transaction_id: {}", 
                     session.getClientId(), session.getTransactionId());
            return jwtToken;
        } catch (Exception e) {
            log.error("Failed to generate JWT access token for session: {}", session.getAuthSession(), e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "JWT access token generation failed", e);
        }
    }

}
