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
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import io.mosip.certify.util.VpParsingUtil;
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
    private VpParsingUtil vpParsingUtil;

    @Autowired
    private IarSessionRepository iarSessionRepository;

    @Autowired
    private RestTemplate restTemplate;

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

    @Override
    public IarResponse processAuthorizationRequest(IarRequest iarRequest) throws CertifyException {
        log.info("Processing IAR for client_id: {}, response_type: {}", 
                 iarRequest.getClientId(), iarRequest.getResponseType());

        try {
            // Validate the request
            validateIarRequest(iarRequest);

            // Generate auth session
            String authSession = generateAuthSession();

            // For now, always require interaction (hardcoded logic)
            // Later this will be replaced with business logic to determine
            // if presentation is actually needed based on client and credentials
            if (requireInteractionByDefault || shouldRequireInteraction(iarRequest)) {
                return generateOpenId4VpRequest(iarRequest, authSession);
            } else {
                // Direct authorization without interaction
                return createDirectAuthorizationResponse(authSession);
            }

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
        String authSession = "session-" + UUID.randomUUID().toString();
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

        log.debug("IAR request validation successful for client: {}", iarRequest.getClientId());
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

            // Use transaction ID from verify service response instead of generating random one
            String transactionId = verifyResponse.getTransactionId();
            if (!StringUtils.hasText(transactionId)) {
                // Fallback to generated ID if verify service doesn't provide one
                transactionId = IarConstants.TRANSACTION_ID_PREFIX + UUID.randomUUID().toString().substring(0, 8);
                log.warn("No transaction ID from verify service, using generated: {}", transactionId);
            } else {
                log.info("Using transaction_id from verify service: {} for auth_session: {}", transactionId, authSession);
            }
            
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
            // Create presentation definition for the verify service
            PresentationDefinition presentationDefinition = createConfigurablePresentationDefinition();

            // Create verify service request
            VerifyVpRequest verifyRequest = new VerifyVpRequest();
            verifyRequest.setClientId(iarRequest.getClientId());
            verifyRequest.setPresentationDefinition(presentationDefinition);
            verifyRequest.setResponseModesSupported(Arrays.asList("direct-post", "direct-post.jwt"));
            verifyRequest.setEncryptionRequired(true);

            // Set up headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<VerifyVpRequest> requestEntity = new HttpEntity<>(verifyRequest, headers);

            // Make the API call
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
            log.warn("No authorization details found in verify service response, using fallback values");
            // Use fallback values from configuration
            openId4VpRequest.setResponseType(openid4vpResponseType);
            openId4VpRequest.setResponseMode(openid4vpResponseMode);
            openId4VpRequest.setClientId(iarRequest.getClientId());
            openId4VpRequest.setResponseUri(openid4vpResponseUri);
            openId4VpRequest.setPresentationDefinition(createConfigurablePresentationDefinition());
            return openId4VpRequest;
        }

        // Use response from verify service
        openId4VpRequest.setResponseType(
            StringUtils.hasText(authDetails.getResponseType()) ? 
            authDetails.getResponseType() : openid4vpResponseType
        );
        
        openId4VpRequest.setResponseMode(
            StringUtils.hasText(authDetails.getResponseMode()) ? 
            authDetails.getResponseMode() : openid4vpResponseMode
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
            // Call actual VP Verifier service at /vp-submission/direct-post
            VpVerificationResponse verificationResponse = callVpVerifierService(
                presentationRequest.getOpenid4vpPresentation(), 
                session.getRequestId()
            );

            IarPresentationResponse response = new IarPresentationResponse();
            if ("ok".equals(verificationResponse.getStatus())) {
                // Step 18: Successful verification
                String authorizationCode = generateAndStoreAuthorizationCode(presentationRequest.getAuthSession());
                response.setStatus(IarConstants.STATUS_OK);
                response.setAuthorizationCode(authorizationCode);
                log.info("VP verification successful for auth_session: {}, request_id: {}", 
                         presentationRequest.getAuthSession(), session.getRequestId());
            } else {
                // Step 18: Failed verification
                response.setStatus(IarConstants.STATUS_ERROR);
                response.setError(verificationResponse.getError() != null ? 
                                 verificationResponse.getError() : IarConstants.INVALID_REQUEST);
                response.setErrorDescription(verificationResponse.getErrorDescription() != null ?
                                           verificationResponse.getErrorDescription() : "VP verification failed");
                log.warn("VP verification failed for auth_session: {}, request_id: {}, error: {}", 
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
     * Mock VP Verifier interaction
     * TODO: Replace with actual API call to VP Verifier's /oid4vp/response endpoint
     */
    /**
     * Call VP Verifier service to verify the presentation
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
            String vpToken = vpParsingUtil.extractVpToken(openid4vpPresentation, openid4vpResponseMode);
            String presentationSubmission = vpParsingUtil.extractPresentationSubmission(
                openid4vpPresentation, openid4vpResponseMode, defaultPresentationDefinitionId);
            
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
            
            String vpVerifierUrl = verifyServiceBaseUrl + "/vp-submission/direct-post";
            log.debug("Calling VP Verifier at: {} with request_id: {}", vpVerifierUrl, requestId);
            
            ResponseEntity<VpVerificationResponse> responseEntity = restTemplate.postForEntity(
                    vpVerifierUrl, requestEntity, VpVerificationResponse.class);
                    
            VpVerificationResponse response = responseEntity.getBody();
            if (response == null) {
                throw new CertifyException("vp_verification_failed", "Empty response from VP Verifier service");
            }
            
            log.info("VP Verifier response - status: {}, request_id: {}", 
                     response.getStatus(), response.getRequestId());
            return response;
            
        } catch (Exception e) {
            log.error("Failed to call VP Verifier service for request_id: {}", requestId, e);
            throw new CertifyException("vp_verification_failed", "VP Verifier service call failed", e);
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
     * Creates presentation definition using configurable properties
     */
    private PresentationDefinition createConfigurablePresentationDefinition() {
        PresentationDefinition presentationDefinition = new PresentationDefinition();
        presentationDefinition.setId(defaultPresentationId);

        // Create input descriptors
        List<InputDescriptor> inputDescriptors = Arrays.asList(
            createIdentityInputDescriptor(),
            createContractInputDescriptor()
        );
        presentationDefinition.setInputDescriptors(inputDescriptors);

        return presentationDefinition;
    }

    /**
     * Creates identity input descriptor for given_name and family_name using configurable paths
     */
    private InputDescriptor createIdentityInputDescriptor() {
        InputDescriptor inputDescriptor = new InputDescriptor();
        inputDescriptor.setId(identityDescriptorId);

        InputConstraints constraints = new InputConstraints();
        List<FieldConstraint> fields = Arrays.asList(
            createFieldConstraint(givenNamePath),
            createFieldConstraint(familyNamePath)
        );
        constraints.setFields(fields);
        inputDescriptor.setConstraints(constraints);

        return inputDescriptor;
    }

    /**
     * Creates contract input descriptor for contract_id using configurable path
     */
    private InputDescriptor createContractInputDescriptor() {
        InputDescriptor inputDescriptor = new InputDescriptor();
        inputDescriptor.setId(contractDescriptorId);

        InputConstraints constraints = new InputConstraints();
        List<FieldConstraint> fields = Arrays.asList(
            createFieldConstraint(contractIdPath)
        );
        constraints.setFields(fields);
        inputDescriptor.setConstraints(constraints);

        return inputDescriptor;
    }

    /**
     * Creates field constraint for the given JSON path
     */
    private FieldConstraint createFieldConstraint(String jsonPath) {
        FieldConstraint fieldConstraint = new FieldConstraint();
        fieldConstraint.setPath(Arrays.asList(jsonPath));
        return fieldConstraint;
    }

    /**
     * Determines if interaction should be required based on business logic
     * Currently hardcoded, will be replaced with actual business logic
     */
    private boolean shouldRequireInteraction(IarRequest iarRequest) {
        // Hardcoded logic - always require interaction for now
        // Later this will check:
        // - Client configuration
        // - Credential type being requested
        // - User authentication status
        // - Policy requirements
        return true;
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
        // For testing, generate a simple JWT-like token
        // In real implementation, this would be a proper signed JWT
        String accessToken = "access_token_" + UUID.randomUUID().toString().replace("-", "");
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
