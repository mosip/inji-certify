/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.services.KeyManagerConstants;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpireSeconds;

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
        String identityData = session.getIdentityData();
        if (!StringUtils.hasText(identityData)) {
            log.warn("Identity data is null or empty for session: {}, transaction_id: {}",
                    session.getAuthSession(), session.getTransactionId());
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Identity data is required but not found in session");
        }

        String scope = session.getScope();
        if (!StringUtils.hasText(scope)) {
            log.warn("Scope is null or empty for session: {}, transaction_id: {}",
                    session.getAuthSession(), session.getTransactionId());
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Scope is required but not found in session");
        }

        return generateSignedJwt(identityData, scope, session.getClientId(), issuer, audience, expirySeconds);
    }

    /**
     * Generate a signed JWT access token using keymanager service.
     * This method accepts raw parameters directly without requiring an IarSession object.
     *
     * @param identityData The identity data (subject) for the JWT
     * @param scope The scope for the JWT
     * @param clientId The client ID (can be null for pre-authorized code flow)
     * @param issuer The issuer URI for the JWT
     * @param audience The audience for the JWT
     * @param expirySeconds Token expiration time in seconds from now
     * @return Signed JWT string
     */
    public String generateSignedJwt(String identityData, String scope, String clientId,
                                     String issuer, String audience, int expirySeconds) {
        try {
            if (!StringUtils.hasText(identityData)) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Identity data is required");
            }
            if (!StringUtils.hasText(scope)) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Scope is required");
            }

            // Current time
            Instant now = Instant.now();
            long issuedAt = now.getEpochSecond();
            long expiresAt = issuedAt + expirySeconds;

            // Build JWT payload as JSON
            Map<String, Object> payload = new HashMap<>();
            payload.put("iss", issuer);
            payload.put("sub", identityData);
            payload.put("aud", audience);
            payload.put("iat", issuedAt);
            payload.put("exp", expiresAt);
            payload.put("client_id", clientId);
            payload.put("scope", scope);
            log.debug("Added scope '{}' to JWT", scope);

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
            signatureRequest.setValidateJson(true);
            signatureRequest.setB64JWSHeaderParam(true);
            signatureRequest.setSignAlgorithm("RS256");

            // Sign using keymanager service
            JWTSignatureResponseDto response = signatureService.jwsSign(signatureRequest);
            String jwtString = response.getJwtSignedData();

            log.debug("Generated JWT access token for client_id: {}", clientId);

            return jwtString;

        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to generate signed JWT", e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "JWT generation failed", e);
        }
    }
}
