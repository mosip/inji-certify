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
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

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

    // Removed unused presentation-related configuration properties

    @Value("${mosip.certify.iar.openid4vp.response-type:vp_token}")
    private String openid4vpResponseType;

    @Value("${mosip.certify.iar.openid4vp.response-mode:iar-post.jwt}")
    private String openid4vpResponseMode;

    @Value("${mosip.certify.iar.session.prefix:session-}")
    private String sessionPrefix;

    @Value("${mosip.certify.iar.token.access-token-prefix:access_token_}")
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

    @Override
    public IarResponse processAuthorizationRequest(IarRequest iarRequest) throws CertifyException {
        log.info("Processing IAR for client_id: {}, response_type: {}, scope: {}", 
                 iarRequest.getClientId(), iarRequest.getResponseType(), iarRequest.getScope());

        try {
            // Validate the request
            validateIarRequest(iarRequest);

            // Generate auth session
            String authSession = generateAuthSession();

            // Always require interaction (no direct authorization path)
            return generateOpenId4VpRequest(iarRequest, authSession);

        } catch (CertifyException e) {
            log.error("IAR processing failed for client: {}, scope: {}, error: {}", 
                      iarRequest.getClientId(), iarRequest.getScope(), e.getErrorCode(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during IAR processing for client: {}, scope: {}", 
                      iarRequest.getClientId(), iarRequest.getScope(), e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "IAR processing failed", e);
        }
    }

    @Override
    public String generateAuthSession() {
        // Generate dynamic auth_session for production security
        String authSession = sessionPrefix + UUID.randomUUID().toString();
        log.debug("Generated dynamic auth session: {}", authSession);
        return authSession;
    }

    @Override
    public void validateIarRequest(IarRequest iarRequest) throws CertifyException {
        log.debug("Validating IAR request for client: {}", iarRequest.getClientId());

        // Field presence is enforced at controller via Bean Validation on UnifiedIarRequest
        // Here we keep domain/business validation only.

        // Validate response_type
        if (!IarConstants.RESPONSE_TYPE_CODE.equals(iarRequest.getResponseType())) {
            throw new CertifyException(IarConstants.UNSUPPORTED_RESPONSE_TYPE, 
                                     "Unsupported response_type: " + iarRequest.getResponseType());
        }

        // Validate code_challenge_method
        if (!IarConstants.CODE_CHALLENGE_METHOD_S256.equals(iarRequest.getCodeChallengeMethod()) &&
            !IarConstants.CODE_CHALLENGE_METHOD_PLAIN.equals(iarRequest.getCodeChallengeMethod())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        log.debug("IAR request validation successful for client: {}, scope: {}", 
                  iarRequest.getClientId(), iarRequest.getScope());
    }

    @Override
    public IarResponse generateOpenId4VpRequest(IarRequest iarRequest, String authSession) throws CertifyException {
        log.info("Generating OpenID4VP request for auth_session: {}", authSession);

        try {
            IarResponse response = new IarResponse();
            response.setStatus(IarConstants.STATUS_REQUIRE_INTERACTION);
            response.setType(IarConstants.TYPE_OPENID4VP_PRESENTATION);
            response.setAuthSession(authSession);

            // Call verify service to get VP request and transaction ID
            VerifyVpResponse verifyResponse = callVerifyServiceForVpRequest(iarRequest);
            
            // Convert verify response to OpenId4VpRequest
            OpenId4VpRequest openId4VpRequest = convertToOpenId4VpRequest(verifyResponse, iarRequest);
            response.setOpenid4vpRequest(openId4VpRequest);

            // Use transaction ID from verify service response - this is required
            String transactionId = verifyResponse.getTransactionId();
            if (!StringUtils.hasText(transactionId)) {
                log.error("No transaction ID provided by verify service - this is required for VP verification");
                throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, 
                    "Verify service did not provide transaction ID");
            }
            
            log.info("Using transaction_id from verify service: {} for auth_session: {}", transactionId, authSession);
            
            // Store complete IAR request details for later validation
            IarSession iarSession = new IarSession();
            iarSession.setAuthSession(authSession);
            iarSession.setTransactionId(transactionId);
            iarSession.setRequestId(verifyResponse.getRequestId());
            iarSession.setVerifyNonce(verifyResponse.getAuthorizationDetails() != null ? 
                                      verifyResponse.getAuthorizationDetails().getNonce() : null);
            // Convert expiresAt from milliseconds to LocalDateTime
            if (verifyResponse.getExpiresAt() != null) {
                iarSession.setExpiresAt(LocalDateTime.ofInstant(
                    java.time.Instant.ofEpochMilli(verifyResponse.getExpiresAt()),
                    java.time.ZoneOffset.UTC));
            }
            iarSession.setClientId(iarRequest.getClientId());
            // Store responseUri from verify service for later VP submission
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
    

    /**
     * Call verify service to generate VP request - Certify only forwards the request
     */
    private VerifyVpResponse callVerifyServiceForVpRequest(IarRequest iarRequest) throws CertifyException {
        log.info("Calling verify service for VP request generation for client_id: {}", iarRequest.getClientId());

        try {
            // Create verify service request with minimal data - let Verify service handle everything
            VerifyVpRequest verifyRequest = new VerifyVpRequest();
            verifyRequest.setClientId(iarRequest.getClientId());
            verifyRequest.setResponseModesSupported(Arrays.asList(
                directPostResponseMode, 
                directPostJwtResponseMode
            ));
            verifyRequest.setEncryptionRequired(true);

            // 🔑 Forward scope as PresentationDefinitionId
            if (StringUtils.hasText(iarRequest.getScope())) {
                verifyRequest.setPresentationDefinitionId(iarRequest.getScope());
            }

            // Set up headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<VerifyVpRequest> requestEntity = new HttpEntity<>(verifyRequest, headers);

            // Make the API call to VP verifier using configured endpoint
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

    /**
     * Convert verify service response to OpenId4VpRequest - only handle response_mode mapping
     */
    private OpenId4VpRequest convertToOpenId4VpRequest(VerifyVpResponse verifyResponse, IarRequest iarRequest) {
        OpenId4VpRequest openId4VpRequest = new OpenId4VpRequest();
        
        // Extract authorization details from verify service response
        VerifyVpResponse.AuthorizationDetails authDetails = verifyResponse.getAuthorizationDetails();
        if (authDetails == null) {
            log.error("No authorization details found in verify service response - this is required for production");
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Invalid response from verify service: missing authorization details");
        }

        // Forward all fields from verify service as-is
        openId4VpRequest.setResponseType(authDetails.getResponseType());
        openId4VpRequest.setClientId(authDetails.getClientId() != null ? authDetails.getClientId() : iarRequest.getClientId());
        openId4VpRequest.setNonce(authDetails.getNonce());
        openId4VpRequest.setPresentationDefinition(authDetails.getPresentationDefinition());
        
        // Only handle response_mode mapping from direct-post → iar-post and direct-post.jwt → iar-post.jwt
        String responseMode = authDetails.getResponseMode();
        if (StringUtils.hasText(responseMode)) {
            String normalizedIncoming = responseMode.replace('_', '-');
            String normalizedDirect = directPostResponseMode != null ? directPostResponseMode.replace('_', '-') : "direct-post";
            String normalizedDirectJwt = directPostJwtResponseMode != null ? directPostJwtResponseMode.replace('_', '-') : "direct-post.jwt";

            if (normalizedIncoming.equalsIgnoreCase(normalizedDirect)) {
                responseMode = iarPostResponseMode;
            } else if (normalizedIncoming.equalsIgnoreCase(normalizedDirectJwt)) {
                responseMode = iarPostJwtResponseMode;
            }
        }
        openId4VpRequest.setResponseMode(responseMode);
        
        // Use response_uri from Verify service
        openId4VpRequest.setResponseUri(authDetails.getResponseUri());

        log.info("Successfully converted verify service response to OpenId4VpRequest for client_id: {}", iarRequest.getClientId());
        log.debug("OpenId4VpRequest - responseType: {}, responseMode: {}, responseUri: {}, nonce: {}", 
                  openId4VpRequest.getResponseType(), openId4VpRequest.getResponseMode(), 
                  openId4VpRequest.getResponseUri(), openId4VpRequest.getNonce());
        log.debug("Using verify service values - transactionId: {}, requestId: {}, expiresAt: {}", 
                  verifyResponse.getTransactionId(), verifyResponse.getRequestId(), verifyResponse.getExpiresAt());

        return openId4VpRequest;
    }

    @Override
    public IarPresentationResponse processVpPresentationResponse(IarPresentationRequest presentationRequest) throws CertifyException {
        log.info("Processing VP presentation for auth_session: {}", presentationRequest.getAuthSession());

        try {
            // Validate auth_session (step 14)
            if (!isValidAuthSession(presentationRequest.getAuthSession())) {
                log.warn("Invalid auth_session: {}", presentationRequest.getAuthSession());
                throw new InvalidRequestException(IarConstants.INVALID_AUTH_SESSION);
            }

            // Get IAR session to retrieve request_id for VP verification
            Optional<IarSession> sessionOpt = iarSessionRepository.findByAuthSession(presentationRequest.getAuthSession());
            if (sessionOpt.isEmpty()) {
                throw new CertifyException("invalid_request", "Invalid auth_session");
            }
            IarSession session = sessionOpt.get();

            // VP Verifier interaction (steps 15-17)
            // Get verification results using transaction ID - Verify service handles VP processing internally
            VpVerificationResponse verificationResponse = getVpVerificationResult(session.getTransactionId());

            IarPresentationResponse response = new IarPresentationResponse();
            if ("ok".equals(verificationResponse.getStatus())) {
                // Step 18: ACTUAL CRYPTOGRAPHIC VERIFICATION SUCCESSFUL
                String authorizationCode = generateAndStoreAuthorizationCode(presentationRequest.getAuthSession());
                response.setStatus(IarConstants.STATUS_OK);
                response.setAuthorizationCode(authorizationCode);
                log.info("Authorization code generated after successful VP cryptographic verification for auth_session: {}, request_id: {}", 
                         presentationRequest.getAuthSession(), session.getRequestId());
            } else {
                // Step 18: ACTUAL CRYPTOGRAPHIC VERIFICATION FAILED
                response.setStatus(IarConstants.STATUS_ERROR);
                response.setError(verificationResponse.getError() != null ? 
                                 verificationResponse.getError() : IarConstants.INVALID_REQUEST);
                response.setErrorDescription(verificationResponse.getErrorDescription() != null ?
                                           verificationResponse.getErrorDescription() : "VP cryptographic verification failed");
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

    // Removed duplicate field-presence validation; controller-level bean validation enforces structure

    /**
     * Validates auth_session against stored IAR sessions
     */
    private boolean isValidAuthSession(String authSession) {
        boolean isValid = iarSessionRepository.findByAuthSession(authSession).isPresent();
        log.debug("Validated auth_session: {}, result: {}", authSession, isValid);
        return isValid;
    }

    /**
     * Get VP verification results using transaction ID
     */
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
                String status = (String) verificationResult.get("status");
                
                if (verificationSuccessStatus.equals(status)) {
                    response.setStatus("ok");
                    response.setVerificationDetails(verificationResult);
                    log.info("VP cryptographic verification successful for transaction_id: {}", transactionId);
                } else {
                    response.setStatus("error");
                    response.setError("verification_failed");
                    response.setErrorDescription("VP cryptographic verification failed: " + verificationResult.get("errorDescription"));
                    response.setVerificationDetails(verificationResult);
                    log.warn("VP cryptographic verification failed for transaction_id: {}, status: {}", transactionId, status);
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
    /**
     * Generates an authorization code for successful VP verification
     */
    private String generateAndStoreAuthorizationCode(String authSession) throws CertifyException {
        String authCode = IarConstants.AUTH_CODE_PREFIX + UUID.randomUUID().toString().substring(0, 8);
        log.debug("Generated authorization code: {} for auth_session: {}", authCode, authSession);
        
        // Update the IAR session with the authorization code
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
        log.info("Processing OAuth token request for client_id: {}, grant_type: {}", 
                 tokenRequest.getClientId(), tokenRequest.getGrantType());

        try {
            // Validate token request
            validateTokenRequest(tokenRequest);

            // Validate authorization code and get session
            IarSession session = validateAuthorizationCode(tokenRequest);

            // Mark authorization code as used
            session.setIsCodeUsed(true);
            iarSessionRepository.save(session);

            // Generate access token and c_nonce
            OAuthTokenResponse response = new OAuthTokenResponse();
            response.setAccessToken(generateAccessToken());
            response.setTokenType("Bearer");
            response.setExpiresIn(3600); // 1 hour
            response.setCNonce(generateCNonce());
            response.setCNonceExpiresIn(300); // 5 minutes
            
            log.info("Token generated successfully for client_id: {}", tokenRequest.getClientId());
            return response;

        } catch (CertifyException e) {
            log.error("Token request validation failed for client_id: {}, error: {}", 
                      tokenRequest.getClientId(), e.getErrorCode(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during token processing for client_id: {}", 
                      tokenRequest.getClientId(), e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Token processing failed", e);
        }
    }

    /**
     * Validate OAuth token request parameters
     */
    private void validateTokenRequest(OAuthTokenRequest tokenRequest) throws CertifyException {
        log.debug("Validating token request for client_id: {}", tokenRequest.getClientId());

        // Validate grant_type
        if (!StringUtils.hasText(tokenRequest.getGrantType())) {
            throw new CertifyException("invalid_request", "Missing grant_type parameter");
        }

        if (!"authorization_code".equals(tokenRequest.getGrantType())) {
            throw new CertifyException("unsupported_grant_type", 
                                     "Unsupported grant_type: " + tokenRequest.getGrantType());
        }

        // Validate required parameters for authorization_code grant
        if (!StringUtils.hasText(tokenRequest.getCode())) {
            throw new CertifyException("invalid_request", "Missing code parameter");
        }

        if (!StringUtils.hasText(tokenRequest.getClientId())) {
            throw new CertifyException("invalid_request", "Missing client_id parameter");
        }

        log.debug("Token request validation successful for client_id: {}", tokenRequest.getClientId());
    }

    /**
     * Validate authorization code from IAR flow with proper database validation
     */
    private IarSession validateAuthorizationCode(OAuthTokenRequest tokenRequest) throws CertifyException {
        log.debug("Validating authorization code: {} for client_id: {}", 
                  tokenRequest.getCode(), tokenRequest.getClientId());

        if (!StringUtils.hasText(tokenRequest.getCode())) {
            throw new CertifyException("invalid_grant", "Invalid authorization code");
        }

        // Validate authorization code format
        if (!tokenRequest.getCode().startsWith(IarConstants.AUTH_CODE_PREFIX)) {
            throw new CertifyException("invalid_grant", "Invalid authorization code format");
        }

        // Find the IAR session by authorization code
        Optional<IarSession> sessionOpt = iarSessionRepository.findByAuthorizationCode(tokenRequest.getCode());
        if (!sessionOpt.isPresent()) {
            throw new CertifyException("invalid_grant", "Authorization code not found");
        }

        IarSession session = sessionOpt.get();

        // Validate code hasn't been used already
        if (Boolean.TRUE.equals(session.getIsCodeUsed())) {
            throw new CertifyException("invalid_grant", "Authorization code already used");
        }

        // Validate code hasn't expired (10 minutes)
        if (session.getCodeIssuedAt() != null && 
            session.getCodeIssuedAt().isBefore(LocalDateTime.now().minusMinutes(10))) {
            throw new CertifyException("invalid_grant", "Authorization code expired");
        }

        // Validate client_id matches
        if (!tokenRequest.getClientId().equals(session.getClientId())) {
            throw new CertifyException("invalid_grant", "Client ID mismatch");
        }

        log.debug("Authorization code validation successful for client_id: {}", tokenRequest.getClientId());
        return session;
    }

    /**
     * Generate access token for credential issuance
     */
    private String generateAccessToken() {
        // Generate access token for credential issuance
        String accessToken = accessTokenPrefix + UUID.randomUUID().toString().replace("-", "");
        log.debug("Generated access token: {}", accessToken.substring(0, 20) + "...");
        return accessToken;
    }

    /**
     * Generate c_nonce for proof of possession
     */
    private String generateCNonce() {
        String cNonce = IarConstants.NONCE_PREFIX + UUID.randomUUID().toString().substring(0, 16);
        log.debug("Generated c_nonce: {}", cNonce);
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
            return processVpPresentationResponse(presentationRequest);
        }

        // Controller validation guarantees one valid flow; default to initial flow if not presentation
        if (!hasAuthSession || !hasVp) {
            log.info("Processing initial authorization request for client_id: {}", unifiedRequest.getClientId());
            IarRequest iarRequest = new IarRequest();
            iarRequest.setResponseType(unifiedRequest.getResponseType());
            iarRequest.setClientId(unifiedRequest.getClientId());
            iarRequest.setCodeChallenge(unifiedRequest.getCodeChallenge());
            iarRequest.setCodeChallengeMethod(unifiedRequest.getCodeChallengeMethod());
            iarRequest.setRedirectUri(unifiedRequest.getRedirectUri());
            iarRequest.setInteractionTypesSupported(unifiedRequest.getInteractionTypesSupported());
            iarRequest.setRedirectToWeb(unifiedRequest.getRedirectToWeb());
            iarRequest.setScope(unifiedRequest.getScope());
            return processAuthorizationRequest(iarRequest);
        }
        // Should not reach here due to controller validation
        log.error("Invalid unified IAR request - neither initial authorization nor VP presentation response");
        throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
    }

}
