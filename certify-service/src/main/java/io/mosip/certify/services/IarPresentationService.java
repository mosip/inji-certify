/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.databind.JsonNode;
import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.dto.IarAuthorizationRequest;
import io.mosip.certify.core.dto.IarAuthorizationResponse;
import io.mosip.certify.core.dto.VpVerificationResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.IarSessionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import jakarta.annotation.PostConstruct;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Service for handling VP Presentation processing
 * Handles VP submission to verifier and verification result processing
 */
@Slf4j
@Service
public class IarPresentationService {

    @Autowired
    private IarSessionRepository iarSessionRepository;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${mosip.certify.verify.service.vp-result-endpoint:http://localhost:8080}")
    private String verifyServiceVpResultEndpoint;

    @Value("${mosip.certify.iar.verification.success-status:SUCCESS}")
    private String verificationSuccessStatus;

    @Value("${mosip.certify.iar.authorization-code.length:24}")
    private int authorizationCodeLength;

    @Value("#{'${mosip.certify.iar.identity-data:uin,vid,UIN,UID}'.split(',')}")
    private Set<String> identityKeys;

    /**
     * Validate required configuration properties at startup
     */
    @PostConstruct
    public void validateConfiguration() {
        if (!StringUtils.hasText(verifyServiceVpResultEndpoint)) {
            throw new IllegalStateException("mosip.certify.verify.service.vp-result-endpoint must be configured");
        }
        if (!StringUtils.hasText(verificationSuccessStatus)) {
            throw new IllegalStateException("mosip.certify.iar.verification.success-status must be configured");
        }
        log.info("IarPresentationService configuration validation successful");
    }

    /**
     * Process VP presentation and return authorization response
     */
    public IarAuthorizationResponse processVpPresentation(IarAuthorizationRequest presentationRequest) throws CertifyException {
        log.info("Processing VP presentation for auth_session: {}", presentationRequest.getAuthSession());

        try {
            Optional<IarSession> sessionOpt = iarSessionRepository.findByAuthSession(presentationRequest.getAuthSession());
            if (sessionOpt.isEmpty()) {
                log.warn("Invalid auth_session: {}", presentationRequest.getAuthSession());
                throw new CertifyException("invalid_request", "Invalid auth_session");
            }
            IarSession session = sessionOpt.get();

            submitVpToVerifier(session.getResponseUri(), 
                             presentationRequest.getOpenid4vpPresentation(),
                             session.getRequestId(), 
                             session.getTransactionId());

            VpVerificationResponse verificationResponse = getVpVerificationResult(session.getTransactionId());

            IarAuthorizationResponse response = new IarAuthorizationResponse();
            if (IarStatus.OK.getValue().equals(verificationResponse.getStatus())) {
                String identity = extractIdentity(verificationResponse);

                if (identity == null || identity.isEmpty()) {
                    throw new CertifyException("invalid_vp", "VP does not contain identity attributes (UIN/VID)");
                }

                session.setIdentityData(identity);
                iarSessionRepository.save(session);
                String authorizationCode = generateAndStoreAuthorizationCode(session);
                response.setStatus(IarStatus.OK);
                response.setAuthorizationCode(authorizationCode);
                log.info("Authorization code generated after successful VP cryptographic verification for auth_session: {}, request_id: {}", 
                         presentationRequest.getAuthSession(), session.getRequestId());
            } else {
                response.setStatus(IarStatus.ERROR);
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
            throw new CertifyException("unknown_error", "VP presentation processing failed", e);
        }
    }

    /**
     * Submit VP presentation to verifier service
     */
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
            
            log.debug("Using requestId: {} for Verify service", requestId);
            
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

            var response = restTemplate.exchange(
                responseUri,
                HttpMethod.POST,
                requestEntity,
                String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("Successfully submitted VP presentation to verify service, response status: {}",
                        response.getStatusCode());
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

    /**
     * Get VP verification result from verifier service
     */
    private VpVerificationResponse getVpVerificationResult(String transactionId) throws CertifyException {
        try {
            String vpResultUrl = verifyServiceVpResultEndpoint + "/" + transactionId;
            log.debug("Getting verification results from: {}", vpResultUrl);
            
            var resultResponse = restTemplate.exchange(
                vpResultUrl, HttpMethod.GET, new HttpEntity<>(new HttpHeaders()), 
                new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {}
            );
            
            Map<String, Object> verificationResult = resultResponse.getBody();
            log.info("VP verification result received for transaction_id: {}", transactionId);
            
            VpVerificationResponse response = new VpVerificationResponse();
            response.setRequestId(transactionId);
            
            if (verificationResult != null) {
                String vpResultStatus = (String) verificationResult.get("vpResultStatus");
                log.debug("Verify service vpResultStatus: {}, expected success value: {}", vpResultStatus, verificationSuccessStatus);
                
                if (verificationSuccessStatus.equals(vpResultStatus)) {
                    response.setStatus(IarStatus.OK.getValue());
                    response.setVerificationDetails(verificationResult);
                    log.info("VP cryptographic verification successful for transaction_id: {}, vpResultStatus: {}", transactionId, vpResultStatus);
                } else {
                    response.setStatus(IarStatus.ERROR.getValue());
                    response.setError("verification_failed");
                    response.setErrorDescription("VP cryptographic verification failed: " + verificationResult.get("errorDescription"));
                    response.setVerificationDetails(verificationResult);
                    log.warn("VP cryptographic verification failed for transaction_id: {}, vpResultStatus: {}", transactionId, vpResultStatus);
                }
            } else {
                response.setStatus(IarStatus.ERROR.getValue());
                response.setError("no_verification_result");
                response.setErrorDescription("No verification result available from verify service");
                log.error("No verification result available for transaction_id: {}", transactionId);
            }
            
            return response;
            
        } catch (Exception e) {
            log.error("Failed to get VP verification results for transaction_id: {}", transactionId, e);
            
            VpVerificationResponse errorResponse = new VpVerificationResponse();
            errorResponse.setStatus(IarStatus.ERROR.getValue());
            errorResponse.setRequestId(transactionId);
            errorResponse.setError("verification_result_error");
            errorResponse.setErrorDescription("Failed to retrieve verification results: " + e.getMessage());
            
            return errorResponse;
        }
    }

    /**
     * Generate and store authorization code
     */
    private String generateAndStoreAuthorizationCode(IarSession session) throws CertifyException {
        // Idempotency guard: if an authorization code already exists for this session
        if (StringUtils.hasText(session.getAuthorizationCode())) {
            // Check if the existing code has already been used - if so, this is an error
            if (Boolean.TRUE.equals(session.getIsCodeUsed())) {
                log.error("Authorization code already used for auth_session: {}, cannot reuse", session.getAuthSession());
                throw new CertifyException("invalid_request", 
                    "Authorization code for this session has already been used. Please start a new authorization flow.");
            }
            log.info("Authorization code already exists for auth_session: {}, returning existing code", session.getAuthSession());
            return session.getAuthorizationCode();
        }

        // Validate minimum length requirement
        if (authorizationCodeLength < 24) {
            throw new CertifyException("invalid_configuration", 
                "Authorization code length must be at least 24 characters. Current value: " + authorizationCodeLength);
        }
        
        // Generate random bytes based on configured length
        // For Base64 URL encoding, we need approximately 3/4 of the target length in bytes
        int byteLength = (int) Math.ceil(authorizationCodeLength * 0.75);
        byte[] randomBytes = new byte[byteLength];
        new java.security.SecureRandom().nextBytes(randomBytes);
        String encoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        
        // Ensure we have enough characters, pad if necessary
        if (encoded.length() < authorizationCodeLength) {
            byte[] additionalBytes = new byte[16];
            new java.security.SecureRandom().nextBytes(additionalBytes);
            String additionalEncoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(additionalBytes);
            encoded = (encoded + additionalEncoded).substring(0, authorizationCodeLength);
        }
        
        String authCode = "iar_auth_" + encoded.substring(0, authorizationCodeLength);
        log.debug("Generated authorization code for auth_session: {} (length: {})", session.getAuthSession(), authCode.length());
        
        session.setAuthorizationCode(authCode);
        session.setCodeIssuedAt(LocalDateTime.now());
        iarSessionRepository.save(session);
        log.info("Authorization code stored for auth_session: {}", session.getAuthSession());
        
        return authCode;
    }

    private String extractIdentity(VpVerificationResponse verificationResponse) {

        Object detailsObj = verificationResponse.getVerificationDetails();
        if (!(detailsObj instanceof Map)) {
            return null;
        }

        Map<String, Object> details = (Map<String, Object>) detailsObj;

        Object vcResultsObj = details.get("vcResults");
        if (!(vcResultsObj instanceof List)) {
            return null;
        }

        List<Map<String, Object>> vcResults = (List<Map<String, Object>>) vcResultsObj;

        for (Map<String, Object> vcEntry : vcResults) {

            Object vcStringObj = vcEntry.get("vc");
            if (!(vcStringObj instanceof String)) {
                continue;
            }

            String vcJson = (String) vcStringObj;
            String extracted = extractIdentityFromVc(vcJson);

            if (extracted != null && !extracted.isEmpty()) {
                return extracted;
            }
        }
        return null;
    }


    private String extractIdentityFromVc(String vcJson) {
        try {
            JsonNode root = objectMapper.readTree(vcJson);

            JsonNode cs = root.path("credentialSubject");
            if (cs.isMissingNode()) {
                return null;
            }

            Iterator<Map.Entry<String, JsonNode>> fields = cs.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();

                if (identityKeys.contains(entry.getKey())) {
                    return entry.getValue().asText();
                }
            }

        } catch (Exception ignored) {}

        return null;
    }

}
