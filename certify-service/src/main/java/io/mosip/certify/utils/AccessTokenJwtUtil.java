/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.services.KeyManagerConstants;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for generating signed JWT access tokens using keymanager service
 * Creates JWT tokens with only the claims validated by AccessTokenValidationFilter
 */
@Slf4j
@Component
public class AccessTokenJwtUtil {

    @Autowired
    private SignatureService signatureService;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Generate a signed JWT access token using keymanager service
     * 
     * @param session The IAR session containing client and transaction information
     * @param issuer The issuer URI for the JWT
     * @param audience The audience for the JWT
     * @param expirySeconds Token expiration time in seconds from now
     * @return Signed JWT string
     */
    public String generateSignedJwt(IarSession session, String issuer, String audience, int expirySeconds) {
        try {
            // Current time
            Instant now = Instant.now();
            long issuedAt = now.getEpochSecond();
            long expiresAt = issuedAt + expirySeconds;

            // Build JWT payload as JSON
            Map<String, Object> payload = new HashMap<>();
            payload.put("iss", issuer);
            payload.put("sub", session.getTransactionId());
            payload.put("aud", audience);
            payload.put("iat", issuedAt);
            payload.put("exp", expiresAt);
            payload.put("client_id", session.getClientId());
            
            // Add scope from session (dynamically extracted from authorization_details)
            String scope = session.getScope();
            if (!StringUtils.hasText(scope)) {
                log.warn("Scope is null or empty for session: {}, transaction_id: {}", 
                    session.getAuthSession(), session.getTransactionId());
                throw new RuntimeException("Scope is required but not found in session");
            }
            payload.put("scope", scope);
            log.debug("Added scope '{}' to JWT for transaction_id: {}", scope, session.getTransactionId());

            // Generate c_nonce and add to JWT
            String cNonce = generateCNonce();
            payload.put("c_nonce", cNonce);
            payload.put("c_nonce_expires_in", 300); 
            log.debug("Added c_nonce '{}' to JWT for transaction_id: {}", cNonce, session.getTransactionId());

            // Convert payload to JSON string
            String payloadJson = objectMapper.writeValueAsString(payload);
            String base64Payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes());

            // Create JWT signature request
            JWSSignatureRequestDto signatureRequest = new JWSSignatureRequestDto();
            signatureRequest.setApplicationId(KeyManagerConstants.CERTIFY_SERVICE_APP_ID);
            signatureRequest.setReferenceId(KeyManagerConstants.EMPTY_REF_ID);
            signatureRequest.setDataToSign(base64Payload);
            signatureRequest.setIncludePayload(true);
            signatureRequest.setIncludeCertificate(false);
            signatureRequest.setIncludeCertHash(false);
            signatureRequest.setValidateJson(false);
            signatureRequest.setB64JWSHeaderParam(false);
            signatureRequest.setSignAlgorithm("RS256");

            // Sign using keymanager service
            JWTSignatureResponseDto response = signatureService.jwsSign(signatureRequest);
            String jwtString = response.getJwtSignedData();

            log.debug("Generated JWT access token for client_id: {}, transaction_id: {}", 
                     session.getClientId(), session.getTransactionId());
            
            return jwtString;

        } catch (Exception e) {
            log.error("Failed to generate signed JWT for session: {}", session.getAuthSession(), e);
            throw new RuntimeException("JWT generation failed", e);
        }
    }

    /**
     * Generate a cryptographically secure c_nonce following eSignet pattern
     * 
     * @return Generated c_nonce string
     */
    private String generateCNonce() {
        String cNonce = java.util.UUID.randomUUID().toString();
        log.debug("Generated c_nonce following eSignet pattern (length: {})", cNonce.length());
        return cNonce;
    }
}
