/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * PKCE (Proof Key for Code Exchange) utility class
 * Implements RFC 7636 specification for OAuth 2.0 PKCE
 */
@Slf4j
public class PkceUtil {

    private static final Base64.Encoder URL_SAFE_ENCODER = Base64.getUrlEncoder().withoutPadding();

    /**
     * Validates PKCE code_verifier against code_challenge
     * 
     * @param codeVerifier The code verifier from the token request
     * @param codeChallenge The code challenge from the authorization request
     * @param codeChallengeMethod The code challenge method (S256 or plain)
     * @return true if validation succeeds, false otherwise
     */
    public static boolean validateCodeVerifier(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
        if (!StringUtils.hasText(codeVerifier) || !StringUtils.hasText(codeChallenge) || !StringUtils.hasText(codeChallengeMethod)) {
            log.warn("PKCE validation failed: missing required parameters");
            return false;
        }

        try {
            switch (codeChallengeMethod.toUpperCase()) {
                case "S256":
                    return validateS256CodeVerifier(codeVerifier, codeChallenge);
                case "PLAIN":
                    return validatePlainCodeVerifier(codeVerifier, codeChallenge);
                default:
                    log.warn("Unsupported code challenge method: {}", codeChallengeMethod);
                    return false;
            }
        } catch (Exception e) {
            log.error("PKCE validation failed with exception", e);
            return false;
        }
    }

    /**
     * Validates S256 code verifier (SHA256 hash of code_verifier)
     */
    private static boolean validateS256CodeVerifier(String codeVerifier, String codeChallenge) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            String computedChallenge = URL_SAFE_ENCODER.encodeToString(hash);
            
            boolean isValid = computedChallenge.equals(codeChallenge);
            if (!isValid) {
                log.warn("S256 PKCE validation failed: computed challenge does not match");
            }
            return isValid;
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-256 algorithm not available", e);
            return false;
        }
    }

    /**
     * Validates plain code verifier (direct comparison)
     */
    private static boolean validatePlainCodeVerifier(String codeVerifier, String codeChallenge) {
        boolean isValid = codeVerifier.equals(codeChallenge);
        if (!isValid) {
            log.warn("Plain PKCE validation failed: code verifier does not match challenge");
        }
        return isValid;
    }

    /**
     * Generates a code challenge from code verifier using S256 method
     * 
     * @param codeVerifier The code verifier
     * @return The code challenge
     */
    public static String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return URL_SAFE_ENCODER.encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-256 algorithm not available", e);
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
