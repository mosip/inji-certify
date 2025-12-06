package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

@Service
@Slf4j
public class PreAuthorizedCodeService {

    @Autowired
    private VCICacheService vciCacheService;

    @Value("${mosip.certify.access-token.expiry-seconds:600}")
    private int accessTokenExpirySeconds;

    @Value("${mosip.certify.c-nonce.expiry-seconds:300}")
    private int cNonceExpirySeconds;

    @Value("${mosip.certify.pre-auth-code.single-use:true}")
    private boolean singleUsePreAuthCode;

    @Value("${mosip.certify.identifier}")
    private String issuerIdentifier;

    @Value("${mosip.certify.pre-auth.default-expiry-seconds:600}")
    private int defaultExpirySeconds;

    @Value("${mosip.certify.pre-auth.min-expiry-seconds:60}")
    private int minExpirySeconds;

    @Value("${mosip.certify.pre-auth.max-expiry-seconds:86400}")
    private int maxExpirySeconds;

    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    public String generatePreAuthorizedCode(PreAuthorizedRequest request) {
        log.info("Generating pre-authorized code for credential configuration: {}",
                request.getCredentialConfigurationId());

        validatePreAuthorizedRequest(request);

        int expirySeconds = request.getExpiresIn() != null ? request.getExpiresIn() : defaultExpirySeconds;

        if (expirySeconds < minExpirySeconds || expirySeconds > maxExpirySeconds) {
            log.error("expires_in {} out of bounds [{}, {}]", expirySeconds, minExpirySeconds, maxExpirySeconds);
            throw new InvalidRequestException(
                    String.format("expires_in must be between %d and %d seconds", minExpirySeconds, maxExpirySeconds));
        }

        String offerId = UUID.randomUUID().toString();
        String preAuthCode = generateUniquePreAuthCode();

        // Store data in cache
        long currentTime = System.currentTimeMillis();
        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(request.getCredentialConfigurationId())
                .claims(request.getClaims())
                .txnCode(request.getTxCode())
                .createdAt(currentTime)
                .expiresAt(currentTime + (expirySeconds * 1000L)).build();

        vciCacheService.setPreAuthCodeData(preAuthCode, codeData);

        CredentialOfferResponse offerResponse = buildCredentialOffer(request.getCredentialConfigurationId(), preAuthCode, request.getTxCode());
        vciCacheService.setCredentialOffer(offerId, offerResponse);

        String offerUri = buildCredentialOfferUri(offerId);
        log.info("Successfully generated pre-authorized code with offer ID: {}", offerId);

        return offerUri;
    }

    private void validatePreAuthorizedRequest(PreAuthorizedRequest request) {
        Map<String, Object> metadata = vciCacheService.getIssuerMetadata();
        Map<String, Object> supportedConfigs = (Map<String, Object>) metadata
                .get(Constants.CREDENTIAL_CONFIGURATIONS_SUPPORTED);

        if (supportedConfigs == null || !supportedConfigs.containsKey(request.getCredentialConfigurationId())) {
            log.error("Invalid credential configuration ID: {}", request.getCredentialConfigurationId());
            throw new InvalidRequestException(ErrorConstants.INVALID_CREDENTIAL_CONFIGURATION_ID);
        }

        Map<String, Object> config = (Map<String, Object>) supportedConfigs.get(request.getCredentialConfigurationId());
        Map<String, Object> requiredClaims = (Map<String, Object>) config.get(Constants.CLAIMS);

        validateClaims(requiredClaims, request.getClaims());
    }

    private void validateClaims(Map<String, Object> requiredClaims, Map<String, Object> providedClaims) {
        if (requiredClaims == null || requiredClaims.isEmpty()) {
            return;
        }

        if (providedClaims == null) {
            providedClaims = Collections.emptyMap();
        }

        List<String> missingClaims = new ArrayList<>();
        List<String> unknownClaims = new ArrayList<>();

        for (Map.Entry<String, Object> entry : requiredClaims.entrySet()) {
            Map<String, Object> claimAttrs = (Map<String, Object>) entry.getValue();
            Boolean mandatory = claimAttrs.containsKey(Constants.MANDATORY)
                    ? (Boolean) claimAttrs.get(Constants.MANDATORY)
                    : Boolean.FALSE;

            if (Boolean.TRUE.equals(mandatory)) {
                if (!providedClaims.containsKey(entry.getKey()) ||
                        providedClaims.get(entry.getKey()) == null) {
                    missingClaims.add(entry.getKey());
                }
            }
        }

        for (String providedClaim : providedClaims.keySet()) {
            if (!requiredClaims.containsKey(providedClaim)) {
                unknownClaims.add(providedClaim);
            }
        }

        if (!missingClaims.isEmpty()) {
            log.error("Missing mandatory claims: {}", missingClaims);
            throw new InvalidRequestException(
                    String.format("Missing mandatory claims: %s", String.join(", ", missingClaims)));
        }

        if (!unknownClaims.isEmpty()) {
            log.error("Unknown claims provided: {}", unknownClaims);
            throw new InvalidRequestException(
                    String.format("Unknown claims: %s", String.join(", ", unknownClaims)));
        }
    }

    public CredentialOfferResponse getCredentialOffer(String offerId) {
        log.info("Retrieving credential offer for ID: {}", offerId);

        if (!isValidUUID(offerId)) {
            log.error("Invalid offer_id format: {}", offerId);
            throw new InvalidRequestException("Invalid offer_id format");
        }

        CredentialOfferResponse offer = vciCacheService.getCredentialOffer(offerId);

        if (offer == null) {
            log.error("Credential offer not found or expired for ID: {}", offerId);
            throw new CertifyException("offer_not_found", "Credential offer not found or expired");
        }

        log.info("Successfully retrieved credential offer for ID: {}", offerId);
        return offer;
    }

    private boolean isValidUUID(String str) {
        if (str == null || str.trim().isEmpty()) {
            return false;
        }
        try {
            UUID.fromString(str.trim());
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String generateUniquePreAuthCode() {
        String preAuthCode;
        int attempts = 0;
        final int MAX_ATTEMPTS = 3;

        do {
            preAuthCode = generateSecureCode(32);
            attempts++;
            if (vciCacheService.getPreAuthCodeData(preAuthCode) == null) {
                return preAuthCode;
            }
        } while (attempts < MAX_ATTEMPTS);

        throw new IllegalStateException(
                "Failed to generate unique pre-authorized code after " + MAX_ATTEMPTS + " attempts");
    }

    private CredentialOfferResponse buildCredentialOffer(String configId, String preAuthCode, String txnCode) {
        CredentialOfferResponse response = new CredentialOfferResponse();
        response.setCredentialIssuer(issuerIdentifier);
        response.setCredentialConfigurationIds(Collections.singletonList(configId));

        // Create the grant object
        Grant grants = new Grant();

        // Create the pre-authorized code grant
        Grant.PreAuthorizedCodeGrant preAuthGrant = new Grant.PreAuthorizedCodeGrant();
        preAuthGrant.setPreAuthorizedCode(preAuthCode);

        // Add tx_code if present
        if (StringUtils.hasText(txnCode)) {
            preAuthGrant.setTxCode(buildTxCodeInfo(txnCode));
        }

        grants.setPreAuthorizedCode(preAuthGrant);
        response.setGrants(grants);

        return response;
    }

    private TxCode buildTxCodeInfo(String txnCode) {
        TxCode txCode = new TxCode();
        txCode.setLength(txnCode.length());
        txCode.setInputMode(txnCode.matches("\\d+") ? "numeric" : "text");
        txCode.setDescription("Enter the code sent to your device");
        return txCode;
    }

    private String buildCredentialOfferUri(String offerId) {
        String offerFetchUrl = domainUrl + "v1/certify/credential-offer-data/" + offerId;
        String encodedUrl = URLEncoder.encode(offerFetchUrl, StandardCharsets.UTF_8);
        return "openid-credential-offer://?credential_offer_uri=" + encodedUrl;
    }

    private String generateSecureCode(int length) {
        StringBuilder code = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            code.append(ALPHANUMERIC.charAt(secureRandom.nextInt(ALPHANUMERIC.length())));
        }
        return code.toString();
    }

    /**
     * Exchange pre-authorized code for access token
     */
    public TokenResponse exchangePreAuthorizedCode(TokenRequest request) {
        log.info("Processing token request for grant_type: {}", request.getGrantType());

        // Retrieve and validate pre-auth code data
        PreAuthCodeData codeData = vciCacheService.getPreAuthCodeData(request.getPreAuthorizedCode());

        validateTokenRequest(request, codeData);

        // Generate access token
        String accessToken = generateAccessToken(codeData);

        // Generate c_nonce
        StringBuilder nonce = new StringBuilder(32);
        for (int i = 0; i < 32; i++) {
            nonce.append(ALPHANUMERIC.charAt(secureRandom.nextInt(ALPHANUMERIC.length())));
        }
        String cNonce = nonce.toString();

        long currentTime = System.currentTimeMillis();
        Transaction transaction = Transaction.builder()
                .credentialConfigurationId(codeData.getCredentialConfigurationId())
                .claims(codeData.getClaims())
                .cNonce(cNonce)
                .cNonceExpiresAt(currentTime + (cNonceExpirySeconds * 1000L))
                .createdAt(currentTime)
                .build();

        vciCacheService.setTransaction(accessToken, transaction);

        log.info("Successfully exchanged pre-authorized code for access token");

        return TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(accessTokenExpirySeconds)
                .cNonce(cNonce)
                .cNonceExpiresIn(cNonceExpirySeconds)
                .build();
    }

    private void validateTokenRequest(TokenRequest request, PreAuthCodeData codeData) {

        // Validate grant type
        if (!Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE.equals(request.getGrantType())) {
            log.error("Unsupported grant type: {}", request.getGrantType());
            throw new CertifyException(ErrorConstants.UNSUPPORTED_GRANT_TYPE, "Grant type not supported");
        }

        if (codeData == null) {
            log.error("Pre-authorized code not found: {}", request.getPreAuthorizedCode());
            throw new CertifyException(ErrorConstants.INVALID_GRANT, "Pre-authorized code not found");
        }

        // Check if already used (blacklisted)
        if (singleUsePreAuthCode && vciCacheService.isCodeBlacklisted(request.getPreAuthorizedCode())) {
            log.error("Pre-authorized code already used: {}", request.getPreAuthorizedCode());
            throw new CertifyException("pre_auth_code_already_used", "Pre-authorized code has already been used");
        }

        // Check expiry
        long currentTime = System.currentTimeMillis();
        if (codeData.getExpiresAt() < currentTime) {
            log.error("Pre-authorized code expired. Expiry: {}, Current: {}", codeData.getExpiresAt(), currentTime);
            throw new CertifyException("pre_auth_code_expired", "Pre-authorized code has expired");
        }

        // Validate transaction code if required
        String expectedTxCode = codeData.getTxnCode();
        if (StringUtils.hasText(expectedTxCode) && !StringUtils.hasText(request.getTxCode())) {
            log.error("Transaction code required but not provided");
            throw new CertifyException("tx_code_required", "Transaction code is required for this pre-authorized code");
        }
        if (StringUtils.hasText(expectedTxCode) && !expectedTxCode.equals(request.getTxCode())) {
            log.error("Transaction code mismatch");
            throw new CertifyException("tx_code_mismatch", "Transaction code does not match");
        }
        // Mark code as used if single-use
        if (singleUsePreAuthCode) {
            vciCacheService.blacklistPreAuthCode(request.getPreAuthorizedCode());
            log.info("Pre-authorized code) marked as used: {}", request.getPreAuthorizedCode());
        }
    }

    /**
     * TEMPORARY WORKAROUND: Generate opaque bearer token
     * TODO: Replace with proper JWT signing once Presentation during Issuance feature is merged
     */
    private String generateAccessToken(PreAuthCodeData codeData) {
        // Generate a cryptographically secure random token
        String accessToken = "at_" + generateSecureCode(64);

        log.warn("WORKAROUND: Generated opaque access token (not JWT). Replace with proper JWT signing.");

        return accessToken;
    }
}