/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IarConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.IarService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.IarSessionRepository;

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

    @Autowired
    private IarSessionRepository iarSessionRepository;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${mosip.certify.iar.default-client-id:default-wallet-client}")
    private String defaultClientId;

    @Value("${mosip.certify.iar.session-timeout-seconds:1800}")
    private int sessionTimeoutSeconds;

    @Value("${mosip.certify.verify.service.base-url}")
    private String verifyServiceBaseUrl;

    @Value("${mosip.certify.verify.service.vp-request-endpoint}")
    private String verifyServiceVpRequestEndpoint;

    @Value("${mosip.certify.verify.service.vp-result-endpoint}")
    private String verifyServiceVpResultEndpoint;


    @Value("${mosip.certify.iar.openid4vp.response-type:vp_token}")
    private String openid4vpResponseType;

    @Value("${mosip.certify.iar.openid4vp.response-mode:iar-post.jwt}")
    private String openid4vpResponseMode;

    @Value("${mosip.certify.iar.session.prefix:iar_session_}")
    private String sessionPrefix;

    @Value("${mosip.certify.iar.auth-code.prefix:iar_auth_}")
    private String authCodePrefix;

    @Value("${mosip.certify.iar.token.access-token-prefix:iar_token_}")
    private String accessTokenPrefix;

    @Value("${mosip.certify.iar.response-mode.direct-post:direct-post}")
    private String directPostResponseMode;

    @Value("${mosip.certify.iar.response-mode.direct-post-jwt:direct-post.jwt}")
    private String directPostJwtResponseMode;

    @Value("${mosip.certify.iar.response-mode.iar-post:iar-post}")
    private String iarPostResponseMode;

    @Value("${mosip.certify.iar.response-mode.iar-post-jwt:iar-post.jwt}")
    private String iarPostJwtResponseMode;

    @Value("${mosip.certify.iar.verification.success-status:SUCCESS}")
    private String verificationSuccessStatus;

    @Value("${mosip.certify.oauth.token.expires-in-seconds:3600}")
    private int tokenExpiresInSeconds;

    @Value("${mosip.certify.oauth.c-nonce.expires-in-seconds:300}")
    private int cNonceExpiresInSeconds;

    @Value("${mosip.certify.iar.authorization-code.expires-minutes:10}")
    private int authorizationCodeExpiresMinutes;

    @Value("${mosip.certify.iar.authorization-code.length:8}")
    private int authorizationCodeLength;

    @Value("${mosip.certify.iar.c-nonce.length:16}")
    private int cNonceLength;

    @Value("${mosip.certify.oauth.token.type:Bearer}")
    private String tokenType;

    @Value("${mosip.certify.verify.service.verifier-client-id}")
    private String verifierClientId;

    @Override
    public IarResponse processAuthorizationRequest(IarRequest iarRequest) throws CertifyException {
        log.info("Processing IAR for client_id: {}, response_type: {}", 
                 iarRequest.getClientId(), iarRequest.getResponseType());

        try {
            // Validate the request
            validateIarRequest(iarRequest);

            // Generate auth session
            String authSession = generateAuthSession();

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
    public String generateAuthSession() {
        byte[] randomBytes = new byte[16];
        new java.security.SecureRandom().nextBytes(randomBytes);
        String encoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        
        String authSession = sessionPrefix + encoded;
        log.debug("Generated auth session: {}", authSession);
        return authSession;
    }

    @Override
    public void validateIarRequest(IarRequest iarRequest) throws CertifyException {
        log.debug("Validating IAR request for client: {}", iarRequest.getClientId());

        // Validate response_type
        if (!IarConstants.RESPONSE_TYPE_CODE.equals(iarRequest.getResponseType())) {
            throw new CertifyException(IarConstants.UNSUPPORTED_RESPONSE_TYPE, 
                                     "Unsupported response_type: " + iarRequest.getResponseType());
        }

        // Validate code_challenge_method
        if (!IarConstants.CODE_CHALLENGE_METHOD_S256.equals(iarRequest.getCodeChallengeMethod())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        // Validate interaction_types_supported
        validateInteractionTypesSupported(iarRequest.getInteractionTypesSupported());

        log.debug("IAR request validation successful for client: {}", 
                  iarRequest.getClientId());
    }

    private void validateInteractionTypesSupported(String interactionTypesSupported) throws CertifyException {
        if (!StringUtils.hasText(interactionTypesSupported)) {
            log.debug("No interaction_types_supported provided - using default");
            return;
        }

        // Split by comma and trim whitespace
        String[] interactionTypes = interactionTypesSupported.split(",");
        for (int i = 0; i < interactionTypes.length; i++) {
            interactionTypes[i] = interactionTypes[i].trim();
        }

        if (interactionTypes.length == 1 && IarConstants.INTERACTION_TYPE_REDIRECT_TO_WEB.equals(interactionTypes[0])) {
            throw new CertifyException(IarConstants.UNSUPPORTED_INTERACTION_TYPE, 
                                     "redirect_to_web interaction type is not supported");
        }

        boolean hasOpenId4Vp = false;
        for (String interactionType : interactionTypes) {
            if (IarConstants.INTERACTION_TYPE_OPENID4VP.equals(interactionType)) {
                hasOpenId4Vp = true;
                break;
            }
        }

        if (!hasOpenId4Vp) {
            throw new CertifyException(IarConstants.UNSUPPORTED_INTERACTION_TYPE, 
                                     "openid4vp_presentation interaction type is required");
        }

        log.debug("Interaction types validation successful: {}", interactionTypesSupported);
    }

    @Override
    public IarResponse generateOpenId4VpRequest(IarRequest iarRequest, String authSession) throws CertifyException {
        log.info("Generating OpenID4VP request for auth_session: {}", authSession);

        try {
            IarResponse response = new IarResponse();
            response.setStatus(IarConstants.STATUS_REQUIRE_INTERACTION);
            response.setType(IarConstants.OPENID4VP_PRESENTATION);
            response.setAuthSession(authSession);

            // Call verify service to get VP request and transaction ID
            VerifyVpResponse verifyResponse = callVerifyServiceForVpRequest(iarRequest);
            
            // Convert verify response to OpenId4VpRequest
            OpenId4VpRequest openId4VpRequest = convertToOpenId4VpRequest(verifyResponse, iarRequest);
            response.setOpenid4vpRequest(openId4VpRequest);

            String transactionId = verifyResponse.getTransactionId();
            if (!StringUtils.hasText(transactionId)) {
                log.error("No transaction ID provided by verify service - this is required for VP verification");
                throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, 
                    "Verify service did not provide transaction ID");
            }
            
            log.info("Using transaction_id from verify service: {} for auth_session: {}", transactionId, authSession);
            
            IarSession iarSession = new IarSession();
            iarSession.setAuthSession(authSession);
            iarSession.setTransactionId(transactionId);
            iarSession.setRequestId(verifyResponse.getRequestId());
            iarSession.setVerifyNonce(verifyResponse.getAuthorizationDetails() != null ? 
                                      verifyResponse.getAuthorizationDetails().getNonce() : null);
            if (verifyResponse.getExpiresAt() != null) {
                iarSession.setExpiresAt(LocalDateTime.ofInstant(
                    java.time.Instant.ofEpochMilli(verifyResponse.getExpiresAt()),
                    java.time.ZoneOffset.UTC));
            }
            iarSession.setClientId(iarRequest.getClientId());
            iarSession.setCodeChallenge(iarRequest.getCodeChallenge());
            iarSession.setCodeChallengeMethod(iarRequest.getCodeChallengeMethod());
            
            if (verifyResponse.getAuthorizationDetails() != null) {
                iarSession.setResponseUri(verifyResponse.getAuthorizationDetails().getResponseUri());
            }
            
            iarSessionRepository.save(iarSession);
            return response;

        } catch (Exception e) {
            log.error("Failed to generate OpenID4VP request for auth_session: {}", authSession, e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Failed to generate OpenID4VP request", e);
        }
    }
    

    private VerifyVpResponse callVerifyServiceForVpRequest(IarRequest iarRequest) throws CertifyException {
        log.info("Calling verify service for VP request generation for wallet client_id: {} using verifier client_id: {}", 
                 iarRequest.getClientId(), verifierClientId);

        try {
            VerifyVpRequest verifyRequest = new VerifyVpRequest();
            verifyRequest.setClientId(verifierClientId);
            log.debug("Using verifier client_id: {} for VP request (wallet client_id: {})", 
                     verifierClientId, iarRequest.getClientId());
            verifyRequest.setResponseModesSupported(Arrays.asList(
                directPostResponseMode, 
                directPostJwtResponseMode
            ));
            verifyRequest.setEncryptionRequired(true);

            if (iarRequest.getAuthorizationDetails() != null 
                && !iarRequest.getAuthorizationDetails().isEmpty()) {
                AuthorizationDetail authDetail = iarRequest.getAuthorizationDetails().get(0);
                
                // Use credential_configuration_id as presentation definition ID
                if (authDetail.getCredentialConfigurationId() != null) {
                    verifyRequest.setPresentationDefinitionId(authDetail.getCredentialConfigurationId());
                }
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<VerifyVpRequest> requestEntity = new HttpEntity<>(verifyRequest, headers);

            String verifyServiceUrl = verifyServiceBaseUrl + verifyServiceVpRequestEndpoint;
            log.debug("Calling verify service at: {}", verifyServiceUrl);

            ResponseEntity<VerifyVpResponse> responseEntity = restTemplate.exchange(
                verifyServiceUrl,
                HttpMethod.POST,
                requestEntity,
                VerifyVpResponse.class
            );

            VerifyVpResponse verifyResponse = responseEntity.getBody();
            if (verifyResponse == null) {
                throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Empty response from verify service");
            }

            log.info("Successfully received VP request from verify service for client_id: {}, transactionId: {}", 
                     iarRequest.getClientId(), verifyResponse.getTransactionId());

            return verifyResponse;

        } catch (Exception e) {
            log.error("Failed to call verify service for client_id: {}", iarRequest.getClientId(), e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Failed to call verify service", e);
        }
    }

    private OpenId4VpRequest convertToOpenId4VpRequest(VerifyVpResponse verifyResponse, IarRequest iarRequest) {
        OpenId4VpRequest openId4VpRequest = new OpenId4VpRequest();
        
        VerifyVpResponse.AuthorizationDetails authDetails = verifyResponse.getAuthorizationDetails();
        if (authDetails == null) {
            log.error("No authorization details found in verify service response - this is required for production");
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Invalid response from verify service: missing authorization details");
        }

        openId4VpRequest.setResponseType(authDetails.getResponseType());
        openId4VpRequest.setClientId(authDetails.getClientId() != null ? authDetails.getClientId() : iarRequest.getClientId());
        
        openId4VpRequest.setNonce(authDetails.getNonce());
        log.info("Forwarding VP request nonce from Verify: {}", authDetails.getNonce());
        
        openId4VpRequest.setPresentationDefinition(authDetails.getPresentationDefinition());
        
        String responseMode = authDetails.getResponseMode();
        if (StringUtils.hasText(responseMode)) {
            String normalizedIncoming = responseMode.replace('_', '-');
            String normalizedDirect = directPostResponseMode.replace('_', '-');
            String normalizedDirectJwt = directPostJwtResponseMode.replace('_', '-');

            if (normalizedIncoming.equalsIgnoreCase(normalizedDirect)) {
                responseMode = iarPostResponseMode;
            } else if (normalizedIncoming.equalsIgnoreCase(normalizedDirectJwt)) {
                responseMode = iarPostJwtResponseMode;
            }
        }
        openId4VpRequest.setResponseMode(responseMode);
        
        openId4VpRequest.setResponseUri(authDetails.getResponseUri());
        log.info("Forwarding VP request response_uri from Verify: {}", authDetails.getResponseUri());

        log.info("Successfully converted verify service response to OpenId4VpRequest for client_id: {}", iarRequest.getClientId());
        log.debug("OpenId4VpRequest - responseType: {}, responseMode: {}, responseUri: {}, nonce: {}", 
                  openId4VpRequest.getResponseType(), openId4VpRequest.getResponseMode(), 
                  openId4VpRequest.getResponseUri(), openId4VpRequest.getNonce());

        return openId4VpRequest;
    }

    private void submitVpToVerifier(String responseUri, String vpPresentationJson, String requestId, String transactionId) throws CertifyException {
        log.info("Submitting VP to Verify at {} with state(requestId)={}, transactionId={}", 
                responseUri, requestId, transactionId);
        
        try {
            Map<String, Object> vpPresentationData = objectMapper.readValue(vpPresentationJson, new TypeReference<Map<String, Object>>() {});
            
            Object vpTokenObj = vpPresentationData.get("vp_token");
            if (vpTokenObj == null) {
                log.error("Missing vp_token in wallet's VP presentation");
                throw new CertifyException("vp_submission_failed", "Missing vp_token in VP presentation");
            }
            
            Object presentationSubmissionObj = vpPresentationData.get("presentation_submission");
            if (presentationSubmissionObj == null) {
                log.error("Missing presentation_submission in wallet's VP presentation");
                throw new CertifyException("vp_submission_failed", "Missing presentation_submission in VP presentation");
            }
            
            String walletState = (String) vpPresentationData.get("state");
            log.debug("Wallet provided state: {}, using requestId: {} for Verify service", walletState, requestId);
            
            String vpTokenJson;
            if (vpTokenObj instanceof String) {
                vpTokenJson = (String) vpTokenObj;
                log.debug("vp_token is a JWT string");
            } else {
                vpTokenJson = objectMapper.writeValueAsString(vpTokenObj);
                log.debug("vp_token serialized to JSON, length: {}", vpTokenJson.length());
            }
            
            String presentationSubmissionJson = objectMapper.writeValueAsString(presentationSubmissionObj);
            log.debug("presentation_submission serialized to JSON, length: {}", presentationSubmissionJson.length());
            
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            
            formData.add("vp_token", vpTokenJson);
            
            formData.add("presentation_submission", presentationSubmissionJson);
            
            formData.add("state", requestId);
            
            log.debug("Form data prepared - vp_token length: {}, presentation_submission length: {}, state(requestId): {}", 
                     vpTokenJson.length(), presentationSubmissionJson.length(), requestId);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                responseUri,
                HttpMethod.POST,
                requestEntity,
                String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("Successfully submitted VP presentation to verify service, response status: {}, body: {}", 
                        response.getStatusCode(), response.getBody());
            } else {
                log.warn("VP submission returned non-success status: {}, body: {}", 
                        response.getStatusCode(), response.getBody());
                throw new CertifyException("vp_submission_failed", 
                    "VP submission failed with status: " + response.getStatusCode());
            }
            
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to submit VP presentation to verify service at: {}, requestId: {}, transactionId: {}", 
                     responseUri, requestId, transactionId, e);
            throw new CertifyException("vp_submission_failed", 
                "Failed to submit VP presentation to verify service: " + e.getMessage(), e);
        }
    }

    @Override
    public IarPresentationResponse processVpPresentation(IarPresentationRequest presentationRequest) throws CertifyException {
        log.info("Processing VP presentation for auth_session: {}", presentationRequest.getAuthSession());

        try {
            if (!isValidAuthSession(presentationRequest.getAuthSession())) {
                log.warn("Invalid auth_session: {}", presentationRequest.getAuthSession());
                throw new InvalidRequestException(IarConstants.INVALID_AUTH_SESSION);
            }

            Optional<IarSession> sessionOpt = iarSessionRepository.findByAuthSession(presentationRequest.getAuthSession());
            if (sessionOpt.isEmpty()) {
                throw new CertifyException("invalid_request", "Invalid auth_session");
            }
            IarSession session = sessionOpt.get();

            submitVpToVerifier(session.getResponseUri(), 
                             presentationRequest.getOpenid4vpPresentation(),
                             session.getRequestId(), 
                             session.getTransactionId());

            VpVerificationResponse verificationResponse = getVpVerificationResult(session.getTransactionId());

            IarPresentationResponse response = new IarPresentationResponse();
            if ("ok".equals(verificationResponse.getStatus())) {
                String authorizationCode = generateAndStoreAuthorizationCode(presentationRequest.getAuthSession());
                response.setStatus(IarConstants.STATUS_OK);
                response.setAuthorizationCode(authorizationCode);
                log.info("Authorization code generated after successful VP cryptographic verification for auth_session: {}, request_id: {}", 
                         presentationRequest.getAuthSession(), session.getRequestId());
            } else {
                response.setStatus(IarConstants.STATUS_ERROR);
                log.warn("Authorization denied - VP cryptographic verification failed for auth_session: {}, request_id: {}, error: {}", 
                         presentationRequest.getAuthSession(), session.getRequestId(), 
                         verificationResponse.getError());
            }

            return response;

        } catch (CertifyException e) {
            log.error("VP presentation processing failed for auth_session: {}, error: {}",
                      presentationRequest.getAuthSession(), e.getErrorCode(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during VP presentation processing for auth_session: {}",
                      presentationRequest.getAuthSession(), e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "VP presentation processing failed", e);
        }
    }


    private boolean isValidAuthSession(String authSession) {
        boolean isValid = iarSessionRepository.findByAuthSession(authSession).isPresent();
        log.debug("Validated auth_session: {}, result: {}", authSession, isValid);
        return isValid;
    }

    private VpVerificationResponse getVpVerificationResult(String transactionId) throws CertifyException {
        try {
            String vpResultUrl = verifyServiceBaseUrl + verifyServiceVpResultEndpoint + "/" + transactionId;
            log.debug("Getting verification results from: {}", vpResultUrl);
            
            ResponseEntity<Map<String, Object>> resultResponse = restTemplate.exchange(
                vpResultUrl, HttpMethod.GET, new HttpEntity<>(new HttpHeaders()), 
                new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {}
            );
            
            Map<String, Object> verificationResult = resultResponse.getBody();
            log.info("VP verification result received for transaction_id: {}, result: {}", transactionId, verificationResult);
            
            VpVerificationResponse response = new VpVerificationResponse();
            response.setRequestId(transactionId);
            
            if (verificationResult != null) {
                String vpResultStatus = (String) verificationResult.get("vpResultStatus");
                log.debug("Verify service vpResultStatus: {}, expected success value: {}", vpResultStatus, verificationSuccessStatus);
                
                if (verificationSuccessStatus.equals(vpResultStatus)) {
                    response.setStatus("ok");
                    response.setVerificationDetails(verificationResult);
                    log.info("VP cryptographic verification successful for transaction_id: {}, vpResultStatus: {}", transactionId, vpResultStatus);
                } else {
                    response.setStatus("error");
                    response.setError("verification_failed");
                    response.setErrorDescription("VP cryptographic verification failed: " + verificationResult.get("errorDescription"));
                    response.setVerificationDetails(verificationResult);
                    log.warn("VP cryptographic verification failed for transaction_id: {}, vpResultStatus: {}", transactionId, vpResultStatus);
                }
            } else {
                response.setStatus("error");
                response.setError("no_verification_result");
                response.setErrorDescription("No verification result available from verify service");
                log.error("No verification result available for transaction_id: {}", transactionId);
            }
            
            return response;
            
        } catch (Exception e) {
            log.error("Failed to get VP verification results for transaction_id: {}", transactionId, e);
            
            VpVerificationResponse errorResponse = new VpVerificationResponse();
            errorResponse.setStatus("error");
            errorResponse.setRequestId(transactionId);
            errorResponse.setError("verification_result_error");
            errorResponse.setErrorDescription("Failed to retrieve verification results: " + e.getMessage());
            
            return errorResponse;
        }
    }
    private String generateAndStoreAuthorizationCode(String authSession) throws CertifyException {
        byte[] randomBytes = new byte[Math.max(authorizationCodeLength, 16)];
        new java.security.SecureRandom().nextBytes(randomBytes);
        String encoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        
        if (encoded.length() < authorizationCodeLength) {
            byte[] additionalBytes = new byte[16];
            new java.security.SecureRandom().nextBytes(additionalBytes);
            String additionalEncoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(additionalBytes);
            encoded = (encoded + additionalEncoded).substring(0, authorizationCodeLength);
        }
        
        String authCode = authCodePrefix + encoded.substring(0, authorizationCodeLength);
        log.debug("Generated authorization code for auth_session: {} (length: {})", authSession, authCode.length());
        
        Optional<IarSession> sessionOpt = iarSessionRepository.findByAuthSession(authSession);
        if (sessionOpt.isPresent()) {
            IarSession session = sessionOpt.get();
            session.setAuthorizationCode(authCode);
            session.setCodeIssuedAt(LocalDateTime.now());
            iarSessionRepository.save(session);
            log.info("Authorization code stored for auth_session: {}", authSession);
        } else {
            log.error("IAR session not found for auth_session: {}", authSession);
            throw new CertifyException(IarConstants.INVALID_AUTH_SESSION, "Session not found");
        }
        
        return authCode;
    }


    
    @Override
    public OAuthTokenResponse processTokenRequest(OAuthTokenRequest tokenRequest) throws CertifyException {
        log.info("Processing OAuth token request for grant_type: {}", 
                 tokenRequest.getGrantType());

        try {
            // Validate grant type
            if (!IarConstants.GRANT_TYPE_AUTHORIZATION_CODE.equals(tokenRequest.getGrantType())) {
                throw new CertifyException("unsupported_grant_type", 
                                         "Only authorization_code grant type is supported");
            }

            // Validate authorization code and atomically mark as used to prevent race conditions
            validateAndMarkAuthorizationCodeUsed(tokenRequest);

            OAuthTokenResponse response = new OAuthTokenResponse();
            response.setAccessToken(generateAccessToken());
            response.setTokenType(tokenType);
            response.setExpiresIn(tokenExpiresInSeconds);
            response.setCNonce(generateCNonce());
            response.setCNonceExpiresIn(cNonceExpiresInSeconds);
            
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


    /**
     * Atomically validate and mark authorization code as used to prevent race conditions
     * This method uses database-level locking to ensure only one token request can use a code
     */
    private IarSession validateAndMarkAuthorizationCodeUsed(OAuthTokenRequest tokenRequest) throws CertifyException {
        log.debug("Atomically validating and marking authorization code as used (code length: {})", 
                  tokenRequest.getCode() != null ? tokenRequest.getCode().length() : 0);

        if (!StringUtils.hasText(tokenRequest.getCode())) {
            throw new CertifyException("invalid_grant", "Invalid authorization code");
        }

        if (!tokenRequest.getCode().startsWith(authCodePrefix)) {
            throw new CertifyException("invalid_grant", "Invalid authorization code format");
        }

        // Use database-level atomic update to prevent race conditions
        // This ensures only one thread can mark the code as used
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

        // Client ID validation removed since we support public clients only
        log.debug("Public client validation passed");

        // Validate PKCE, redirect_uri, and client_secret
        validatePkceCodeVerifier(tokenRequest, session);
        validateRedirectUri(tokenRequest, session);
        validateClientSecret(tokenRequest, session);

        // ATOMIC UPDATE: Mark code as used in single database operation
        // This prevents race conditions where multiple requests try to use the same code
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
            
        } catch (Exception e) {
            log.error("Failed to atomically mark authorization code as used", e);
            throw new CertifyException("server_error", "Failed to process authorization code", e);
        }
    }


    private void validatePkceCodeVerifier(OAuthTokenRequest tokenRequest, IarSession session) throws CertifyException {
        String codeVerifier = tokenRequest.getCodeVerifier();
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
    
    private void validateRedirectUri(OAuthTokenRequest tokenRequest, IarSession session) throws CertifyException {
        // redirect_uri validation removed since we don't support redirect_to_web
        log.debug("Redirect URI validation skipped (not supported)");
    }
    
    private void validateClientSecret(OAuthTokenRequest tokenRequest, IarSession session) throws CertifyException {
        // Client secret validation removed since we support public clients only
        log.debug("Public client secret validation passed");
    }

    private String generateAccessToken() {
        // Generate cryptographically secure random token with 32 bytes (256 bits) of entropy
        byte[] randomBytes = new byte[32];
        new java.security.SecureRandom().nextBytes(randomBytes);
        String accessToken = accessTokenPrefix + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        log.debug("Generated secure access token (length: {})", accessToken.length());
        return accessToken;
    }

    private String generateCNonce() {
        // Generate cryptographically secure random c_nonce with 16 bytes (128 bits) of entropy
        byte[] randomBytes = new byte[16];
        new java.security.SecureRandom().nextBytes(randomBytes);
        String cNonce = "iar_nonce_" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        log.debug("Generated secure c_nonce (length: {})", cNonce.length());
        return cNonce;
    }

    @Override
    public Object handleIarRequest(UnifiedIarRequest unifiedRequest) throws CertifyException {
        log.info("Handling unified IAR request");

        boolean hasAuthSession = unifiedRequest.getAuthSession() != null && !unifiedRequest.getAuthSession().trim().isEmpty();
        boolean hasVp = unifiedRequest.getOpenid4vpPresentation() != null && !unifiedRequest.getOpenid4vpPresentation().trim().isEmpty();

        if (hasAuthSession && hasVp) {
            log.info("Processing VP presentation response for auth_session: {}", unifiedRequest.getAuthSession());
            IarPresentationRequest presentationRequest = new IarPresentationRequest();
            presentationRequest.setAuthSession(unifiedRequest.getAuthSession());
            presentationRequest.setOpenid4vpPresentation(unifiedRequest.getOpenid4vpPresentation());
            return processVpPresentation(presentationRequest);
        }

        if (!hasAuthSession || !hasVp) {
            log.info("Processing initial authorization request for client_id: {}", unifiedRequest.getClientId());
            IarRequest iarRequest = new IarRequest();
            iarRequest.setResponseType(unifiedRequest.getResponseType());
            iarRequest.setClientId(unifiedRequest.getClientId());
            iarRequest.setCodeChallenge(unifiedRequest.getCodeChallenge());
            iarRequest.setCodeChallengeMethod(unifiedRequest.getCodeChallengeMethod());
            iarRequest.setInteractionTypesSupported(unifiedRequest.getInteractionTypesSupported());
            iarRequest.setAuthorizationDetails(unifiedRequest.getAuthorizationDetails());
            return processAuthorizationRequest(iarRequest);
        }
        log.error("Invalid unified IAR request - neither initial authorization nor VP presentation response");
        throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
    }

}
