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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import io.mosip.certify.util.VpParsingUtil;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.IarSessionRepository;
import io.mosip.certify.services.PresentationDefinitionConfigService;

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
    private VpParsingUtil vpParsingUtil;

    @Autowired
    private IarSessionRepository iarSessionRepository;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private PresentationDefinitionConfigService presentationDefinitionConfigService;

    @Value("${mosip.certify.iar.default-client-id:default-wallet-client}")
    private String defaultClientId;

    @Value("${mosip.certify.iar.session-timeout-seconds:1800}")
    private int sessionTimeoutSeconds;

    @Value("${mosip.certify.iar.presentation.default-id:employment-check}")
    private String defaultPresentationDefinitionId;


    @Value("${mosip.certify.iar.require-interaction:true}")
    private boolean requireInteractionByDefault;

    @Value("${mosip.certify.verify.service.base-url:http://localhost:8080}")
    private String verifyServiceBaseUrl;

    @Value("${mosip.certify.verify.service.vp-request-endpoint:/v1/verify/vp-request}")
    private String verifyServiceVpRequestEndpoint;

    @Value("${mosip.certify.verify.service.vp-submission-endpoint:/v1/verify/vp-submission/direct-post}")
    private String verifyServiceVpSubmissionEndpoint;

    @Value("${mosip.certify.verify.service.vp-result-endpoint:/v1/verify/vp-result}")
    private String verifyServiceVpResultEndpoint;

    @Value("${mosip.certify.iar.presentation.default-id:employment-check}")
    private String defaultPresentationId;

    @Value("${mosip.certify.iar.presentation.identity-descriptor-id:identity}")
    private String identityDescriptorId;

    @Value("${mosip.certify.iar.presentation.contract-descriptor-id:contract}")
    private String contractDescriptorId;

    @Value("${mosip.certify.iar.presentation.fields.given-name:$.credentialSubject.given_name}")
    private String givenNamePath;

    @Value("${mosip.certify.iar.presentation.fields.family-name:$.credentialSubject.family_name}")
    private String familyNamePath;

    @Value("${mosip.certify.iar.presentation.fields.contract-id:$.credentialSubject.contract_id}")
    private String contractIdPath;

    @Value("${mosip.certify.iar.openid4vp.response-type:vp_token}")
    private String openid4vpResponseType;

    @Value("${mosip.certify.iar.openid4vp.response-mode:iar-post.jwt}")
    private String openid4vpResponseMode;

    @Value("${mosip.certify.iar.openid4vp.response-uri:http://localhost:8090/v1/certify/oauth/iar}")
    private String openid4vpResponseUri;

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

    @Value("#{${mosip.certify.iar.scope.mappings:{'employee_id_vc_ldp':'MOSIPVerifiableCredential','manager_badge_vc_ldp':'MOSIPVerifiableCredential'}}}")
    private Map<String, String> scopeToCredentialTypeMappings;

    @Value("#{${mosip.certify.iar.scope.requires-presentation:{'manager_badge_vc_ldp':true,'employee_id_vc_ldp':true,'VisitorBadge':false}}}")
    private Map<String, Boolean> scopeRequiresPresentationMappings;

    @Value("#{${mosip.certify.iar.client-id.patterns:{'insurance':'InsuranceCredential','land':'LandStatementCredential'}}}")
    private Map<String, String> clientIdPatterns;

    @Override
    public IarResponse processAuthorizationRequest(IarRequest iarRequest) throws CertifyException {
        log.info("Processing IAR for client_id: {}, response_type: {}, scope: {}", 
                 iarRequest.getClientId(), iarRequest.getResponseType(), iarRequest.getScope());

        try {
            // Validate the request
            validateIarRequest(iarRequest);

            // Generate auth session
            String authSession = generateAuthSession();

            // Smart decision based on scope and business logic (OpenID4VCI Section 5.1.2)
            if (shouldRequireInteractionForScope(iarRequest)) {
                return generateOpenId4VpRequest(iarRequest, authSession);
            } else {
                // Direct authorization without interaction
                return createDirectAuthorizationResponse(authSession);
            }

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

        // Validate required fields
        if (!StringUtils.hasText(iarRequest.getResponseType())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(iarRequest.getClientId())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(iarRequest.getCodeChallenge())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(iarRequest.getCodeChallengeMethod())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(iarRequest.getRedirectUri())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

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

        // Validate scope parameter (OpenID4VCI Section 5.1.2)
        validateScopeParameter(iarRequest);

        log.debug("IAR request validation successful for client: {}, scope: {}", 
                  iarRequest.getClientId(), iarRequest.getScope());
    }
    
    /**
     * Validates scope parameter according to OpenID4VCI Section 5.1.2
     * "Credential Issuers MUST ignore unknown scope values in a request"
     * "Multiple scope values MAY be present in a single request whereby each occurrence MUST be interpreted individually"
     */
    private void validateScopeParameter(IarRequest iarRequest) throws CertifyException {
        String scope = iarRequest.getScope();
        
        // Scope is optional, so null/empty is allowed
        if (scope == null || scope.trim().isEmpty()) {
            log.debug("No scope provided in IAR request for client: {}", iarRequest.getClientId());
            return;
        }
        
        // Parse multiple scopes (space-separated as per OAuth 2.0 spec)
        String[] scopes = scope.trim().split("\\s+");
        boolean hasKnownScope = false;
        
        for (String singleScope : scopes) {
            if (isKnownScope(singleScope)) {
                hasKnownScope = true;
                log.debug("Known scope '{}' found for client: {}", singleScope, iarRequest.getClientId());
            } else {
                // As per OpenID4VCI spec: "Credential Issuers MUST ignore unknown scope values"
                log.info("Unknown scope '{}' will be ignored for client: {} (per OpenID4VCI spec)", 
                         singleScope, iarRequest.getClientId());
            }
        }
        
        // Optional: If no known scopes provided, we could warn but should not fail
        if (!hasKnownScope) {
            log.warn("No known scopes provided for client: {}, scope: '{}' - all scopes will be ignored", 
                     iarRequest.getClientId(), scope);
            // Note: We don't throw an exception here as unknown scopes should be ignored, not cause failures
        }
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
            
            iarSessionRepository.save(iarSession);
            return response;

        } catch (Exception e) {
            log.error("Failed to generate OpenID4VP request for auth_session: {}", authSession, e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Failed to generate OpenID4VP request", e);
        }
    }
    

    /**
     * Call verify service to generate VP request instead of hardcoding
     */
    private VerifyVpResponse callVerifyServiceForVpRequest(IarRequest iarRequest) throws CertifyException {
        log.info("Calling verify service for VP request generation for client_id: {}", iarRequest.getClientId());

        try {
            // Create scope-aware presentation definition for the verify service (OpenID4VCI Section 5.1.2)
            PresentationDefinition presentationDefinition = createPresentationDefinitionForScope(iarRequest);

            // Create verify service request
            VerifyVpRequest verifyRequest = new VerifyVpRequest();
            verifyRequest.setClientId(iarRequest.getClientId());
            verifyRequest.setPresentationDefinition(presentationDefinition);
            verifyRequest.setResponseModesSupported(Arrays.asList(
                directPostResponseMode, 
                directPostJwtResponseMode
            ));
            verifyRequest.setEncryptionRequired(true);

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
     * Convert verify service response to OpenId4VpRequest
     */
    private OpenId4VpRequest convertToOpenId4VpRequest(VerifyVpResponse verifyResponse, IarRequest iarRequest) {
        OpenId4VpRequest openId4VpRequest = new OpenId4VpRequest();
        
        // Extract authorization details from verify service response
        VerifyVpResponse.AuthorizationDetails authDetails = verifyResponse.getAuthorizationDetails();
        if (authDetails == null) {
            log.error("No authorization details found in verify service response - this is required for production");
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Invalid response from verify service: missing authorization details");
        }

        // Use response from verify service
        openId4VpRequest.setResponseType(
            StringUtils.hasText(authDetails.getResponseType()) ? 
            authDetails.getResponseType() : openid4vpResponseType
        );
        
        // Map direct-post to iar-post and direct-post.jwt to iar-post.jwt as per OpenID4VCI spec
        String responseMode = authDetails.getResponseMode();
        if (directPostResponseMode.equals(responseMode)) {
            responseMode = iarPostResponseMode;
        } else if (directPostJwtResponseMode.equals(responseMode)) {
            responseMode = iarPostJwtResponseMode;
        }
        
        openId4VpRequest.setResponseMode(
            StringUtils.hasText(responseMode) ? 
            responseMode : openid4vpResponseMode
        );
        
        openId4VpRequest.setClientId(iarRequest.getClientId());
        
        // Use response_uri from verify service
        openId4VpRequest.setResponseUri(
            StringUtils.hasText(authDetails.getResponseUri()) ? 
            authDetails.getResponseUri() : openid4vpResponseUri
        );

        // Use nonce from verify service
        openId4VpRequest.setNonce(authDetails.getNonce());

        // Use presentation definition from verify service response
        openId4VpRequest.setPresentationDefinition(authDetails.getPresentationDefinition());

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
            // Validate the presentation request
            validateIarPresentationRequest(presentationRequest);

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
            // Call VP Verifier service directly - the verify service handles the deferred result internally
            VpVerificationResponse verificationResponse = callVpVerifierService(
                presentationRequest.getOpenid4vpPresentation(), 
                session.getRequestId()
            );

            IarPresentationResponse response = new IarPresentationResponse();
            if ("ok".equals(verificationResponse.getStatus())) {
                // Step 18: ACTUAL CRYPTOGRAPHIC VERIFICATION SUCCESSFUL
                String authorizationCode = generateAndStoreAuthorizationCode(presentationRequest.getAuthSession());
                response.setStatus(IarConstants.STATUS_OK);
                response.setAuthorizationCode(authorizationCode);
                log.info("🎯 AUTHORIZATION CODE GENERATED after successful VP cryptographic verification for auth_session: {}, request_id: {}", 
                         presentationRequest.getAuthSession(), session.getRequestId());
            } else {
                // Step 18: ACTUAL CRYPTOGRAPHIC VERIFICATION FAILED
                response.setStatus(IarConstants.STATUS_ERROR);
                response.setError(verificationResponse.getError() != null ? 
                                 verificationResponse.getError() : IarConstants.INVALID_REQUEST);
                response.setErrorDescription(verificationResponse.getErrorDescription() != null ?
                                           verificationResponse.getErrorDescription() : "VP cryptographic verification failed");
                log.warn("🚨 AUTHORIZATION DENIED - VP cryptographic verification failed for auth_session: {}, request_id: {}, error: {}", 
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

    /**
     * Validates the Verifiable Presentation request
     */
    private void validateIarPresentationRequest(IarPresentationRequest presentationRequest) throws CertifyException {
        log.debug("Validating VP presentation request for auth_session: {}", presentationRequest.getAuthSession());

        if (!StringUtils.hasText(presentationRequest.getAuthSession())) {
            throw new InvalidRequestException(IarConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(presentationRequest.getOpenid4vpPresentation())) {
            throw new InvalidRequestException(IarConstants.INVALID_REQUEST);
        }

        log.debug("VP presentation request validation successful for auth_session: {}", presentationRequest.getAuthSession());
    }

    /**
     * Validates auth_session against stored IAR sessions
     */
    private boolean isValidAuthSession(String authSession) {
        boolean isValid = iarSessionRepository.findByAuthSession(authSession).isPresent();
        log.debug("Validated auth_session: {}, result: {}", authSession, isValid);
        return isValid;
    }

    /**
     * Call VP Verifier service to verify the presentation
     * This method calls the self-hosted verify service directly
     * 
     * @param openid4vpPresentation The VP presentation data
     * @param requestId The request ID to use as state parameter
     * @return VpVerificationResponse from the verifier service
     * @throws CertifyException if verification service call fails
     */
    private VpVerificationResponse callVpVerifierService(String openid4vpPresentation, String requestId) 
            throws CertifyException {
        try {
            log.info("Calling VP Verifier service for request_id: {}", requestId);
            
            // Parse the VP presentation using enhanced parsing utility
            log.debug("Parsing VP presentation for request_id: {}, presentation length: {}, response_mode: {}", 
                     requestId, openid4vpPresentation != null ? openid4vpPresentation.length() : 0, openid4vpResponseMode);
            
            String vpToken = vpParsingUtil.extractVpToken(openid4vpPresentation, openid4vpResponseMode);
            String presentationSubmission = vpParsingUtil.extractPresentationSubmission(
                openid4vpPresentation, openid4vpResponseMode, defaultPresentationDefinitionId);
                
            log.debug("Parsed VP for request_id: {}, vpToken length: {}, presentationSubmission length: {}", 
                     requestId, 
                     vpToken != null ? vpToken.length() : 0, 
                     presentationSubmission != null ? presentationSubmission.length() : 0);
                     
            // Validate extracted data
            if (vpToken == null || vpToken.trim().isEmpty()) {
                log.error("Failed to extract vp_token from presentation for request_id: {}", requestId);
                VpVerificationResponse errorResponse = new VpVerificationResponse();
                errorResponse.setStatus("error");
                errorResponse.setRequestId(requestId);
                errorResponse.setError("invalid_vp_token");
                errorResponse.setErrorDescription("Failed to extract vp_token from presentation");
                return errorResponse;
            }
            
            if (presentationSubmission == null || presentationSubmission.trim().isEmpty()) {
                log.error("Failed to extract presentation_submission for request_id: {}", requestId);
                VpVerificationResponse errorResponse = new VpVerificationResponse();
                errorResponse.setStatus("error");
                errorResponse.setRequestId(requestId);
                errorResponse.setError("invalid_presentation_submission");
                errorResponse.setErrorDescription("Failed to extract presentation_submission");
                return errorResponse;
            }
            
            // Create VP verification request
            VpVerificationRequest verificationRequest = new VpVerificationRequest();
            verificationRequest.setVpToken(vpToken);
            verificationRequest.setPresentationSubmission(presentationSubmission);
            verificationRequest.setState(requestId);
            
            // Prepare form data for VP Verifier service
            String formData = String.format("vp_token=%s&presentation_submission=%s&state=%s",
                    URLEncoder.encode(verificationRequest.getVpToken(), StandardCharsets.UTF_8),
                    URLEncoder.encode(verificationRequest.getPresentationSubmission(), StandardCharsets.UTF_8),
                    URLEncoder.encode(verificationRequest.getState(), StandardCharsets.UTF_8));
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            HttpEntity<String> requestEntity = new HttpEntity<>(formData, headers);
            
            // STEP 1: Submit VP to verify service for processing
            String vpSubmissionUrl = verifyServiceBaseUrl + verifyServiceVpSubmissionEndpoint;
            log.debug("Submitting VP to verifier at: {} with request_id: {}", vpSubmissionUrl, requestId);
            
            ResponseEntity<String> submissionResponse = restTemplate.postForEntity(
                    vpSubmissionUrl, requestEntity, String.class);
            
            log.info("VP submission HTTP response - status: {}, request_id: {}", 
                     submissionResponse.getStatusCode(), requestId);
            
            VpVerificationResponse response = new VpVerificationResponse();
            response.setRequestId(requestId);
            
            if (!submissionResponse.getStatusCode().is2xxSuccessful()) {
                // Failed submission
                response.setStatus("error");
                response.setError("submission_failed");
                response.setErrorDescription("VP submission failed with HTTP status: " + submissionResponse.getStatusCode());
                log.warn("VP submission failed for request_id: {}, HTTP status: {}", 
                         requestId, submissionResponse.getStatusCode());
                return response;
            }
            
            log.info("VP submission successful for request_id: {}, now getting verification results...", requestId);
            
            // STEP 2: Get ACTUAL verification results from verify service
            // We need the transaction ID that was stored when creating the VP request
            // Since we have the requestId, we need to find the session that contains it
            // The requestId should match the one stored in the session
            List<IarSession> allSessions = iarSessionRepository.findAll();
            String transactionId = null;
            
            for (IarSession session : allSessions) {
                if (requestId.equals(session.getRequestId())) {
                    transactionId = session.getTransactionId();
                    log.debug("Found matching session with transaction_id: {} for request_id: {}", transactionId, requestId);
                    break;
                }
            }
            
            if (transactionId == null) {
                log.error("No transaction ID found for request_id: {} - this indicates a session management error", requestId);
                throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, 
                    "Cannot find transaction ID for VP verification - session not found");
            }
            
            String vpResultUrl = verifyServiceBaseUrl + verifyServiceVpResultEndpoint + "/" + transactionId;
            log.debug("Getting verification results from: {}", vpResultUrl);
            
            try {
                // Add a small delay to allow verify service to process the submission
                Thread.sleep(1000); // 1 second delay
                
                ResponseEntity<Map<String, Object>> resultResponse = restTemplate.exchange(
                    vpResultUrl, HttpMethod.GET, new HttpEntity<>(new HttpHeaders()), 
                    new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {}
                );
                
                Map<String, Object> verificationResult = resultResponse.getBody();
                log.info("VP verification result received for request_id: {}, result: {}", requestId, verificationResult);
                
                if (verificationResult != null) {
                    String status = (String) verificationResult.get("status");
                    
                    if (verificationSuccessStatus.equals(status)) {
                        // ACTUAL VERIFICATION SUCCESSFUL
                        response.setStatus("ok");
                        response.setVerificationDetails(verificationResult);
                        log.info("🎯 VP CRYPTOGRAPHIC VERIFICATION SUCCESSFUL for request_id: {}", requestId);
                        
                    } else {
                        // ACTUAL VERIFICATION FAILED
                        response.setStatus("error");
                        response.setError("verification_failed");
                        response.setErrorDescription("VP cryptographic verification failed: " + verificationResult.get("errorDescription"));
                        response.setVerificationDetails(verificationResult);
                        log.warn("🚨 VP CRYPTOGRAPHIC VERIFICATION FAILED for request_id: {}, status: {}", requestId, status);
                    }
                } else {
                    response.setStatus("error");
                    response.setError("no_verification_result");
                    response.setErrorDescription("No verification result available from verify service");
                    log.error("No verification result available for request_id: {}", requestId);
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                response.setStatus("error");
                response.setError("verification_interrupted");
                response.setErrorDescription("Verification process was interrupted");
                log.error("Verification interrupted for request_id: {}", requestId);
                
            } catch (Exception e) {
                response.setStatus("error");
                response.setError("verification_result_error");
                response.setErrorDescription("Failed to retrieve verification results: " + e.getMessage());
                log.error("Failed to get verification results for request_id: {}", requestId, e);
            }
            
            return response;
            
        } catch (Exception e) {
            log.error("Failed to call VP Verifier service for request_id: {}", requestId, e);
            
            // Create an error response instead of throwing exception immediately
            // This allows the cryptographic verification to fail gracefully
            VpVerificationResponse errorResponse = new VpVerificationResponse();
            errorResponse.setStatus("error");
            errorResponse.setRequestId(requestId);
            errorResponse.setError("vp_verification_service_error");
            errorResponse.setErrorDescription("VP Verifier service call failed: " + e.getMessage());
            
            log.info("Returning error response for failed VP verification service call, request_id: {}", requestId);
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

    /**
     * Creates scope-aware presentation definition using configuration service
     * Integrates scope-based logic with configuration-based credential type mapping
     */
    private PresentationDefinition createPresentationDefinitionForScope(IarRequest iarRequest) {
        String scope = iarRequest.getScope();
        String clientId = iarRequest.getClientId();
        
        // Extract credential type from scope first, then fall back to client_id
        String credentialType = extractCredentialTypeFromRequest(iarRequest);
        
        log.info("Creating presentation definition for credential type: {} (scope: {}, client: {})", 
                 credentialType, scope, clientId);
        
        // Use configuration service to get presentation definition - no fallbacks in production
        PresentationDefinition definition = presentationDefinitionConfigService
                .getPresentationDefinition(credentialType);
        
        if (definition == null) {
            log.error("No presentation definition found for credential type: {} - configuration is required", credentialType);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, 
                "Presentation definition not configured for credential type: " + credentialType);
        }
        
        log.debug("Successfully retrieved presentation definition for credential type: {}", credentialType);
        return definition;
    }
    
    /**
     * Extract credential type from IAR request
     * Priority: scope -> client_id patterns -> default
     */
    private String extractCredentialTypeFromRequest(IarRequest iarRequest) {
        String scope = iarRequest.getScope();
        String clientId = iarRequest.getClientId();
        
        // First, try to extract from scope using configuration
        if (StringUtils.hasText(scope)) {
            String[] scopes = scope.trim().split("\\s+");
            String primaryScope = scopes[0];
            
            // Check configured scope mappings
            if (scopeToCredentialTypeMappings.containsKey(primaryScope)) {
                String credentialType = scopeToCredentialTypeMappings.get(primaryScope);
                log.debug("Found configured scope mapping: {} -> {}", primaryScope, credentialType);
                return credentialType;
            } else {
                log.debug("Unknown scope '{}' not in configuration, falling back to client_id extraction", primaryScope);
            }
        }
        
        // Fall back to client_id pattern matching using configuration
        if (StringUtils.hasText(clientId)) {
            for (Map.Entry<String, String> entry : clientIdPatterns.entrySet()) {
                if (clientId.contains(entry.getKey())) {
                    log.debug("Found client_id pattern match: {} contains {} -> {}", 
                             clientId, entry.getKey(), entry.getValue());
                    return entry.getValue();
                }
            }
        }
        
        // No fallbacks in production - explicit configuration required
        log.error("No credential type could be determined for scope '{}' and client_id '{}' - explicit configuration required", scope, clientId);
        throw new CertifyException(ErrorConstants.INVALID_REQUEST, 
            "Cannot determine credential type for request - configure proper scope mappings or client_id patterns");
    }
    

    /**
     * Determines if interaction should be required based on scope and business logic
     * Implements OpenID4VCI Section 5.1.2 scope-based credential request handling
     */
    private boolean shouldRequireInteractionForScope(IarRequest iarRequest) {
        String scope = iarRequest.getScope();
        
        if (scope == null || scope.trim().isEmpty()) {
            log.debug("No scope provided, falling back to default interaction requirement");
            return requireInteractionByDefault;
        }
        
        // Parse multiple scopes (space-separated as per OAuth 2.0 spec)
        String[] scopes = scope.trim().split("\\s+");
        
        for (String singleScope : scopes) {
            if (isKnownScope(singleScope)) {
                // Check if this specific scope requires VP presentation
                if (scopeRequiresPresentation(singleScope)) {
                    log.info("Scope '{}' requires VP presentation for client: {}", singleScope, iarRequest.getClientId());
        return true;
                }
            } else {
                // As per OpenID4VCI spec: "Credential Issuers MUST ignore unknown scope values"
                log.warn("Unknown scope '{}' ignored for client: {}", singleScope, iarRequest.getClientId());
            }
        }
        
        log.info("No scopes require VP presentation for client: {}, scope: {}", iarRequest.getClientId(), scope);
        return false;
    }
    
    /**
     * Check if a scope value is known/supported by this Credential Issuer
     * Uses configuration-driven mappings instead of hardcoded values
     */
    private boolean isKnownScope(String scope) {
        // Check if scope is configured in either mappings
        boolean isInScopeMappings = scopeToCredentialTypeMappings.containsKey(scope);
        boolean isInPresentationMappings = scopeRequiresPresentationMappings.containsKey(scope);
        
        return isInScopeMappings || isInPresentationMappings;
    }
    
    /**
     * Determine if a specific scope requires VP presentation during issuance
     * Uses configuration-driven mappings instead of hardcoded values
     */
    private boolean scopeRequiresPresentation(String scope) {
        // Check configured scope presentation requirements
        if (scopeRequiresPresentationMappings.containsKey(scope)) {
            boolean requiresPresentation = scopeRequiresPresentationMappings.get(scope);
            log.debug("Found configured presentation requirement for scope '{}': {}", scope, requiresPresentation);
            return requiresPresentation;
        }
        
        log.debug("No specific presentation policy configured for scope '{}', using default: {}", 
                 scope, requireInteractionByDefault);
        return requireInteractionByDefault;
    }

    /**
     * Creates direct authorization response when no interaction is needed
     */
    private IarResponse createDirectAuthorizationResponse(String authSession) {
        IarResponse response = new IarResponse();
        response.setStatus(IarConstants.STATUS_COMPLETE);
        response.setAuthSession(authSession);
        // No openid4vp_request needed for direct a     uthorization
        return response;
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

}
