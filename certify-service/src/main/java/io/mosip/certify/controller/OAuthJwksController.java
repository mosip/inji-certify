/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.services.KeyManagerConstants;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

/**
 * Controller to serve JWK set for OAuth access token verification
 * Reference: eSignet's OAuthServiceImpl.getJwks()
 */
@Slf4j
@RestController
@RequestMapping("/oauth")
public class OAuthJwksController {

    @Autowired
    private KeymanagerService keymanagerService;

    /**
     * Get JWK set endpoint for OAuth access token verification
     * 
     * Cached for 5 minutes to improve performance and reduce load on keymanager service.
     * Returns empty keys array if no valid certificates are found (standard OAuth behavior).
     * Only successful responses (200 OK) are cached - errors are not cached to allow retries.
     * 
     * @return ResponseEntity with JWK set containing public keys
     */
    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwks() {
        log.info("Fetching JWK set for CERTIFY_SERVICE_APP_ID");
        
        try {
            Map<String, Object> response = getJwksInternal();
            
            if (response != null && response.containsKey("keys")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> jwkList = (List<Map<String, Object>>) response.get("keys");
                if (jwkList != null && !jwkList.isEmpty()) {
                    log.info("JWK set retrieved successfully with {} keys", jwkList.size());
                    return ResponseEntity.ok(response);
                } else {
                    log.warn("JWK set is empty - no valid certificates available. This may cause token validation failures.");
                    // Return empty keys array per OAuth 2.0 spec
                    return ResponseEntity.ok(response);
                }
            } else {
                log.error("Invalid response structure from getJwksInternal");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("keys", Collections.emptyList());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
            }
            
        } catch (Exception e) {
            log.error("Failed to retrieve JWK set from keymanager service", e);
            // Return empty keys array per OAuth 2.0 spec - clients should handle this gracefully
            // Do NOT cache error responses - allow retries
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("keys", Collections.emptyList());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
        }
    }

    /**
     * Internal method to fetch JWK set - cached for performance
     * Only successful responses are cached (method returns non-null Map)
     */
    @Cacheable(value = "jwks", key = "'oauth-jwks'")
    private Map<String, Object> getJwksInternal() {
        AllCertificatesDataResponseDto allCertificatesDataResponseDto = keymanagerService.getAllCertificates(
                KeyManagerConstants.CERTIFY_SERVICE_APP_ID, Optional.empty());
        
        List<Map<String, Object>> jwkList = new ArrayList<>();
        
        if (allCertificatesDataResponseDto != null && allCertificatesDataResponseDto.getAllCertificates() != null) {
            Arrays.stream(allCertificatesDataResponseDto.getAllCertificates())
                .filter(dto -> dto != null 
                    && StringUtils.hasText(dto.getKeyId()) 
                    && StringUtils.hasText(dto.getCertificateData()))
                .forEach(dto -> {
                    try {
                        Map<String, Object> jwk = getJwk(dto.getKeyId(), dto.getCertificateData(), dto.getExpiryAt());
                        if (jwk != null) {
                            jwkList.add(jwk);
                            log.debug("Added JWK for keyId: {}", dto.getKeyId());
                        }
                    } catch (Exception e) {
                        log.error("Failed to parse the certificate data for keyId: {}", dto.getKeyId(), e);
                        // Continue processing other certificates
                    }
                });
        } else {
            log.warn("No certificates found for CERTIFY_SERVICE_APP_ID");
        }

        Map<String, Object> response = new HashMap<>();
        response.put("keys", jwkList);
        
        return response;
    }

    /**
     * Convert certificate data to JWK format
     * 
     * @param keyId Key identifier
     * @param certificateData PEM encoded certificate
     * @param expiryAt Certificate expiry date
     * @return JWK map, or null if certificate parsing fails or certificate is expired
     * @throws Exception if certificate parsing fails
     */
    private Map<String, Object> getJwk(String keyId, String certificateData, LocalDateTime expiryAt) throws Exception {
        // Validate inputs
        if (!StringUtils.hasText(keyId)) {
            throw new IllegalArgumentException("keyId cannot be null or empty");
        }
        if (!StringUtils.hasText(certificateData)) {
            throw new IllegalArgumentException("certificateData cannot be null or empty");
        }
        
        // Validate certificate is not expired if expiryAt is provided
        if (expiryAt != null && expiryAt.isBefore(LocalDateTime.now())) {
            log.debug("Certificate for keyId: {} has expired, skipping", keyId);
            return null;
        }
        
        // Parse X509 certificate
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate;
        try {
            x509Certificate = (X509Certificate) certificateFactory.generateCertificate(
                    new ByteArrayInputStream(certificateData.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            log.error("Failed to parse X509 certificate for keyId: {}", keyId, e);
            throw new IllegalArgumentException("Invalid certificate format", e);
        }

        // Extract RSA public key
        RSAPublicKey rsaPublicKey;
        try {
            rsaPublicKey = (RSAPublicKey) x509Certificate.getPublicKey();
        } catch (ClassCastException e) {
            log.error("Certificate for keyId: {} does not contain an RSA public key", keyId, e);
            throw new IllegalArgumentException("Certificate must contain an RSA public key", e);
        }
        
        // Get modulus and exponent
        BigInteger modulus = rsaPublicKey.getModulus();
        BigInteger exponent = rsaPublicKey.getPublicExponent();
        
        // Validate modulus and exponent are not null
        if (modulus == null || exponent == null) {
            log.error("Invalid RSA public key for keyId: {} - modulus or exponent is null", keyId);
            throw new IllegalArgumentException("Invalid RSA public key");
        }
        
        // Base64 URL encode modulus and exponent
        String n = Base64.getUrlEncoder().withoutPadding().encodeToString(modulus.toByteArray());
        String e = Base64.getUrlEncoder().withoutPadding().encodeToString(exponent.toByteArray());
        
        // Calculate certificate thumbprint (SHA-256)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] certHash = md.digest(x509Certificate.getEncoded());
        String x5tS256 = Base64.getUrlEncoder().withoutPadding().encodeToString(certHash);
        
        // Get certificate chain - clean PEM format
        String x5c = certificateData
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        
        // Validate cleaned certificate data is not empty
        if (!StringUtils.hasText(x5c)) {
            log.error("Certificate data for keyId: {} is empty after cleaning", keyId);
            throw new IllegalArgumentException("Certificate data is invalid");
        }
        
        // Build JWK according to RFC 7517
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("use", "sig");
        jwk.put("kid", keyId);
        jwk.put("alg", "RS256");
        jwk.put("n", n);
        jwk.put("e", e);
        jwk.put("x5c", Collections.singletonList(x5c));
        jwk.put("x5t#S256", x5tS256);
        
        // Add expiration time if provided (use UTC for consistency across distributed systems)
        if (expiryAt != null) {
            long expEpoch = expiryAt.atZone(ZoneId.of("UTC")).toEpochSecond();
            jwk.put("exp", expEpoch);
        }
        
        return jwk;
    }
}

