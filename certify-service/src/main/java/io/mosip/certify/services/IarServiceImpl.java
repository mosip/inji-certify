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
import java.util.Objects;
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

        log.debug("IAR request validation successful for client: {}", 
                  iarRequest.getClientId());
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
            log.debug("Stored wallet client_id in session: {} (can be null for public clients)", iarRequest.getClientId());
            
            // Store PKCE parameters for token request validation
            iarSession.setCodeChallenge(iarRequest.getCodeChallenge());
            iarSession.setCodeChallengeMethod(iarRequest.getCodeChallengeMethod());
            iarSession.setRedirectUri(iarRequest.getRedirectUri());
            
            log.debug("Stored PKCE parameters - codeChallenge: {}, codeChallengeMethod: {}, redirectUri: {}", 
                     iarRequest.getCodeChallenge(), iarRequest.getCodeChallengeMethod(), iarRequest.getRedirectUri());
            
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
        log.info("Calling verify service for VP request generation for wallet client_id: {} using verifier client_id: {}", 
                 iarRequest.getClientId(), verifierClientId);

        try {
            // Create verify service request with minimal data - let Verify service handle everything
            VerifyVpRequest verifyRequest = new VerifyVpRequest();
            // Use verifier client ID (not wallet's client_id) - wallet client_id is for public client identification
            verifyRequest.setClientId(verifierClientId);
            log.debug("Using verifier client_id: {} for VP request (wallet client_id: {})", 
                     verifierClientId, iarRequest.getClientId());
            verifyRequest.setResponseModesSupported(Arrays.asList(
                directPostResponseMode, 
                directPostJwtResponseMode
            ));
            verifyRequest.setEncryptionRequired(true);

            // Extract presentationDefinitionId from authorization_details
            if (iarRequest.getAuthorizationDetails() != null 
                && !iarRequest.getAuthorizationDetails().isEmpty()) {
                AuthorizationDetail authDetail = iarRequest.getAuthorizationDetails().get(0);
                if (authDetail.getCredentialDefinition() != null 
                    && authDetail.getCredentialDefinition().getType() != null
                    && authDetail.getCredentialDefinition().getType().size() > 1) {
                    verifyRequest.setPresentationDefinitionId(
                        authDetail.getCredentialDefinition().getType().get(1)
                    );
                }
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
        
        // Use nonce from Verify service - critical for cryptographic proof verification
        openId4VpRequest.setNonce(authDetails.getNonce());
        log.info("Forwarding VP request nonce from Verify: {}", authDetails.getNonce());
        
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
        
        // Use response_uri from Verify service - must match domain expected by Verify for VP submission
        openId4VpRequest.setResponseUri(authDetails.getResponseUri());
        log.info("Forwarding VP request response_uri from Verify: {}", authDetails.getResponseUri());

        log.info("Successfully converted verify service response to OpenId4VpRequest for client_id: {}", iarRequest.getClientId());
        log.debug("OpenId4VpRequest - responseType: {}, responseMode: {}, responseUri: {}, nonce: {}", 
                  openId4VpRequest.getResponseType(), openId4VpRequest.getResponseMode(), 
                  openId4VpRequest.getResponseUri(), openId4VpRequest.getNonce());
        log.debug("Using verify service values - transactionId: {}, requestId: {}, expiresAt: {}", 
                  verifyResponse.getTransactionId(), verifyResponse.getRequestId(), verifyResponse.getExpiresAt());

        return openId4VpRequest;
    }

    /**
     * Submit VP presentation to the verify service using the responseUri
     * Parses the wallet's VP presentation JSON and extracts vp_token, presentation_submission, and state
     * Sends data as application/x-www-form-urlencoded with these three fields
     */
    private void submitVpToVerifier(String responseUri, String vpPresentationJson, String requestId, String transactionId) throws CertifyException {
        log.info("Submitting VP to Verify at {} with state(requestId)={}, transactionId={}", 
                responseUri, requestId, transactionId);
        
        try {
            // Parse the wallet's VP presentation JSON to extract the three required fields
            Map<String, Object> vpPresentationData = objectMapper.readValue(vpPresentationJson, new TypeReference<Map<String, Object>>() {});
            
            // Extract vp_token (can be an object or a JWT string)
            Object vpTokenObj = vpPresentationData.get("vp_token");
            if (vpTokenObj == null) {
                log.error("Missing vp_token in wallet's VP presentation");
                throw new CertifyException("vp_submission_failed", "Missing vp_token in VP presentation");
            }
            
            // Extract presentation_submission (should be an object)
            Object presentationSubmissionObj = vpPresentationData.get("presentation_submission");
            if (presentationSubmissionObj == null) {
                log.error("Missing presentation_submission in wallet's VP presentation");
                throw new CertifyException("vp_submission_failed", "Missing presentation_submission in VP presentation");
            }
            
            // Extract state from wallet's response (for validation/logging purposes)
            String walletState = (String) vpPresentationData.get("state");
            log.debug("Wallet provided state: {}, using requestId: {} for Verify service", walletState, requestId);
            
            // Serialize vp_token to JSON string
            String vpTokenJson;
            if (vpTokenObj instanceof String) {
                // If it's already a JWT string, use as-is
                vpTokenJson = (String) vpTokenObj;
                log.debug("vp_token is a JWT string");
            } else {
                // If it's an object, serialize to JSON
                vpTokenJson = objectMapper.writeValueAsString(vpTokenObj);
                log.debug("vp_token serialized to JSON, length: {}", vpTokenJson.length());
            }
            
            // Serialize presentation_submission to JSON string
            String presentationSubmissionJson = objectMapper.writeValueAsString(presentationSubmissionObj);
            log.debug("presentation_submission serialized to JSON, length: {}", presentationSubmissionJson.length());
            
            // Build form body with vp_token, presentation_submission, and state
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            
            // Add vp_token as JSON string
            formData.add("vp_token", vpTokenJson);
            
            // Add presentation_submission as JSON string
            formData.add("presentation_submission", presentationSubmissionJson);
            
            // Add state - use requestId (not transactionId) as this is what Verify service uses for lookup
            formData.add("state", requestId);
            
            log.debug("Form data prepared - vp_token length: {}, presentation_submission length: {}, state(requestId): {}", 
                     vpTokenJson.length(), presentationSubmissionJson.length(), requestId);
            
            // Create headers with form-urlencoded content type
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            // Create request entity with form data
            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
            
            // Submit VP to verify service using POST
            ResponseEntity<String> response = restTemplate.exchange(
                responseUri,
                HttpMethod.POST,
                requestEntity,
                String.class
            );
            
            // Check for successful response (200 OK)
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
            // Re-throw CertifyException as-is
            throw e;
        } catch (Exception e) {
            log.error("Failed to submit VP presentation to verify service at: {}, requestId: {}, transactionId: {}", 
                     responseUri, requestId, transactionId, e);
            throw new CertifyException("vp_submission_failed", 
                "Failed to submit VP presentation to verify service: " + e.getMessage(), e);
        }
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

            // Submit VP presentation to verify service using stored responseUri
            // Parse wallet's VP presentation JSON and extract vp_token, presentation_submission, and state
            // Use requestId as state (Verify service uses requestId for lookup, not transactionId)
            submitVpToVerifier(session.getResponseUri(), 
                             presentationRequest.getOpenid4vpPresentation(),
                             session.getRequestId(), 
                             session.getTransactionId());

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
                // Check vpResultStatus field from Verify service response
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
    /**
     * Generates an authorization code for successful VP verification
     */
    private String generateAndStoreAuthorizationCode(String authSession) throws CertifyException {
        String authCode = IarConstants.AUTH_CODE_PREFIX + UUID.randomUUID().toString().substring(0, authorizationCodeLength);
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
            // Bean Validation is now handled at controller level via @Valid annotation
            // No need for manual validation here

            // Validate authorization code and get session
            IarSession session = validateAuthorizationCode(tokenRequest);

            // Mark authorization code as used
            session.setIsCodeUsed(true);
            iarSessionRepository.save(session);

            // Generate access token and c_nonce
            OAuthTokenResponse response = new OAuthTokenResponse();
            response.setAccessToken(generateAccessToken());
            response.setTokenType(tokenType);
            response.setExpiresIn(tokenExpiresInSeconds);
            response.setCNonce(generateCNonce());
            response.setCNonceExpiresIn(cNonceExpiresInSeconds);
            
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

        // Validate code hasn't expired
        if (session.getCodeIssuedAt() != null && 
            session.getCodeIssuedAt().isBefore(LocalDateTime.now().minusMinutes(authorizationCodeExpiresMinutes))) {
            throw new CertifyException("invalid_grant", "Authorization code expired");
        }

        // Validate client_id matches per RFC 7636 Section 3.2
        // Public clients (null client_id) can use any authorization code
        // Confidential clients must match the client_id from authorization request
        String tokenClientId = tokenRequest.getClientId();
        String sessionClientId = session.getClientId();
        
        // If token request has no client_id, it's a public client - always allowed
        if (tokenClientId == null) {
            log.debug("Public client (no client_id) - validation passed");
        } else if (!Objects.equals(tokenClientId, sessionClientId)) {
            // Confidential client must match the client_id from authorization request
            log.warn("Client ID mismatch - token: {}, session: {}", tokenClientId, sessionClientId);
            throw new CertifyException("invalid_grant", "Client ID mismatch");
        } else {
            log.debug("Client ID validation successful for confidential client: {}", tokenClientId);
        }

        // Validate PKCE code_verifier against stored code_challenge
        validatePkceCodeVerifier(tokenRequest, session);
        
        // Validate redirect_uri matches the one from authorization request
        validateRedirectUri(tokenRequest, session);
        
        // Validate client_secret is not provided for public clients
        validateClientSecret(tokenRequest, session);

        log.debug("Authorization code validation successful for client_id: {}", tokenRequest.getClientId());
        return session;
    }

    /**
     * Validate PKCE code_verifier against stored code_challenge
     * RFC 7636 Section 4.6: Verify code_verifier using code_challenge_method
     */
    private void validatePkceCodeVerifier(OAuthTokenRequest tokenRequest, IarSession session) throws CertifyException {
        String codeVerifier = tokenRequest.getCodeVerifier();
        String codeChallenge = session.getCodeChallenge();
        String codeChallengeMethod = session.getCodeChallengeMethod();
        
        log.debug("PKCE validation - codeVerifier: {}, codeChallenge: {}, codeChallengeMethod: {}", 
                 codeVerifier, codeChallenge, codeChallengeMethod);
        
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
                // S256: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
                java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(codeVerifier.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                computedChallenge = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            } else if (IarConstants.CODE_CHALLENGE_METHOD_PLAIN.equals(codeChallengeMethod)) {
                // Plain: code_challenge = code_verifier
                computedChallenge = codeVerifier;
            } else {
                throw new CertifyException("invalid_request", "Unsupported code_challenge_method: " + codeChallengeMethod);
            }
            
            if (!codeChallenge.equals(computedChallenge)) {
                log.warn("PKCE validation failed - code_challenge mismatch for client_id: {}", tokenRequest.getClientId());
                throw new CertifyException("invalid_grant", "Invalid code_verifier");
            }
            
            log.debug("PKCE validation successful for client_id: {}", tokenRequest.getClientId());
            
        } catch (java.security.NoSuchAlgorithmException e) {
            log.error("SHA-256 algorithm not available for PKCE validation", e);
            throw new CertifyException("server_error", "PKCE validation failed");
        }
    }
    
    /**
     * Validate redirect_uri matches the one from authorization request
     * RFC 6749 Section 4.1.3: redirect_uri MUST be identical to the one in authorization request
     */
    private void validateRedirectUri(OAuthTokenRequest tokenRequest, IarSession session) throws CertifyException {
        String tokenRedirectUri = tokenRequest.getRedirectUri();
        String sessionRedirectUri = session.getRedirectUri();
        
        if (!StringUtils.hasText(tokenRedirectUri)) {
            throw new CertifyException("invalid_request", "redirect_uri is required");
        }
        
        if (!StringUtils.hasText(sessionRedirectUri)) {
            throw new CertifyException("invalid_request", "redirect_uri missing from authorization request");
        }
        
        if (!tokenRedirectUri.equals(sessionRedirectUri)) {
            log.warn("Redirect URI mismatch - token: {}, session: {}", tokenRedirectUri, sessionRedirectUri);
            throw new CertifyException("invalid_grant", "redirect_uri mismatch");
        }
        
        log.debug("Redirect URI validation successful for client_id: {}", tokenRequest.getClientId());
    }
    
    /**
     * Validate client_secret is not provided for public clients
     * RFC 7636 Section 3.2: Public clients MUST NOT use client_secret
     */
    private void validateClientSecret(OAuthTokenRequest tokenRequest, IarSession session) throws CertifyException {
        String clientSecret = tokenRequest.getClientSecret();
        String clientId = tokenRequest.getClientId();
        
        // If client_id is null or empty, it's a public client
        boolean isPublicClient = !StringUtils.hasText(clientId);
        
        if (isPublicClient && StringUtils.hasText(clientSecret)) {
            log.warn("Public client attempted to use client_secret - client_id: {}", clientId);
            throw new CertifyException("invalid_request", "client_secret not allowed for public clients");
        }
        
        // For confidential clients, client_secret validation would be handled by authentication mechanism
        // This implementation focuses on preventing public clients from using client_secret
        
        log.debug("Client secret validation successful for client_id: {} (public: {})", clientId, isPublicClient);
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
        String cNonce = IarConstants.NONCE_PREFIX + UUID.randomUUID().toString().substring(0, cNonceLength);
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
            iarRequest.setAuthorizationDetails(unifiedRequest.getAuthorizationDetails());
            return processAuthorizationRequest(iarRequest);
        }
        // Should not reach here due to controller validation
        log.error("Invalid unified IAR request - neither initial authorization nor VP presentation response");
        throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
    }

}
