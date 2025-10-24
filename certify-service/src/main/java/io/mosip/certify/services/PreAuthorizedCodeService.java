package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
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
    private VCICacheService cacheService;

    @Autowired
    private VCICacheService vciCacheService;

    @Value("${mosip.certify.issuer.identifier:local}")
    private String issuerIdentifier;

    @Value("${mosip.certify.pre-auth.default-expiry-seconds:600}")
    private int defaultExpirySeconds;

    @Value("${mosip.certify.pre-auth.base-url:http://localhost:8090}")
    private String baseUrl;

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    public String generatePreAuthorizedCode(PreAuthorizedRequest request) {
        log.info("Generating pre-authorized code for credential configuration: {}", request.getCredentialConfigurationId());

        // Validate credential configuration exists
        validateCredentialConfiguration(request.getCredentialConfigurationId());

        // Validate claims against metadata
        validateClaims(request.getCredentialConfigurationId(), request.getClaims());

        // Determine expiry
        int expirySeconds = request.getExpiresIn() != null ? request.getExpiresIn() : defaultExpirySeconds;

        // Generate unique IDs
        String offerId = UUID.randomUUID().toString();
        String preAuthCode = generateSecureCode(32);

        // Store data in cache
        long currentTime = System.currentTimeMillis();
        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(request.getCredentialConfigurationId())
                .claims(request.getClaims())
                .txnCode(request.getTxCode())
                .createdAt(currentTime)
                .expiresAt(currentTime + (expirySeconds * 1000L)).build();

        // Cache the pre-auth code data
        cacheService.setPreAuthCodeData(preAuthCode, codeData, expirySeconds);

        // Create credential offer
        CredentialOfferResponse offerResponse = buildCredentialOffer(request.getCredentialConfigurationId(), preAuthCode, request.getTxCode());

        // Cache the credential offer
        cacheService.setCredentialOffer(offerId, offerResponse, expirySeconds);

        // Build and return the URI
        String offerUri = buildCredentialOfferUri(offerId);
        log.info("Successfully generated pre-authorized code with offer ID: {}", offerId);

        return offerUri;
    }

    public CredentialOfferResponse getCredentialOffer(String offerId) {
        if (!isValidUUID(offerId)) {
            throw new InvalidRequestException("Invalid offer_id format");
        }
        CredentialOfferResponse offer = cacheService.getCredentialOffer(offerId);
        if (offer == null) {
            log.error("Credential offer not found or expired for ID: {}", offerId);
            throw new InvalidRequestException(ErrorConstants.CREDENTIAL_OFFER_NOT_FOUND);
        }

        return offer;
    }

    private boolean isValidUUID(String str) {
        try {
            UUID.fromString(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private void validateCredentialConfiguration(String configId) {
        Map<String, Object> metadata = vciCacheService.getIssuerMetadata();
        Map<String, Object> supportedConfigs = (Map<String, Object>) metadata.get(Constants.CREDENTIAL_CONFIGURATIONS_SUPPORTED);

        if (supportedConfigs == null || !supportedConfigs.containsKey(configId)) {
            log.error("Invalid credential configuration ID: {}", configId);
            throw new InvalidRequestException(ErrorConstants.INVALID_CREDENTIAL_CONFIGURATION_ID);
        }
    }

    private void validateClaims(String configId, Map<String, Object> providedClaims) {
        Map<String, Object> metadata = vciCacheService.getIssuerMetadata();

        Map<String, Object> supportedConfigs = (Map<String, Object>) metadata.get(Constants.CREDENTIAL_CONFIGURATIONS_SUPPORTED);

        Map<String, Object> config = (Map<String, Object>) supportedConfigs.get(configId);
        Map<String, Object> requiredClaims = (Map<String, Object>) config.get(Constants.CLAIMS);

        if (requiredClaims != null) {
            for (Map.Entry<String, Object> entry : requiredClaims.entrySet()) {
                Map<String, Object> claimAttrs = (Map<String, Object>) entry.getValue();
                Boolean mandatory = (Boolean) claimAttrs.get(Constants.MANDATORY);

                if (Boolean.TRUE.equals(mandatory)) {
                    if (!providedClaims.containsKey(entry.getKey()) || providedClaims.get(entry.getKey()) == null) {
                        log.error("Missing mandatory claim: {}", entry.getKey());
                        throw new InvalidRequestException(String.format(ErrorConstants.MISSING_MANDATORY_CLAIM, entry.getKey()));
                    }
                }
            }

            for (String providedClaim : providedClaims.keySet()) {
                if (!requiredClaims.containsKey(providedClaim)) {
                    log.error("Unknown claim provided: {}", providedClaim);
                    throw new InvalidRequestException(String.format("Unknown claim: %s", providedClaim));
                }
            }

        }
    }

    private CredentialOfferResponse buildCredentialOffer(String configId, String preAuthCode, String txnCode) {
        CredentialOfferResponse response = new CredentialOfferResponse();
        response.setCredentialIssuer(issuerIdentifier);
        response.setCredentialConfigurationIds(Collections.singletonList(configId));

        Grant grants = new Grant();
        Grant.PreAuthorizedCodeGrant grant = new Grant.PreAuthorizedCodeGrant();
        grant.setPreAuthorizedCode(preAuthCode);
        grant.setTxCode(StringUtils.hasText(txnCode) ? buildTxCodeInfo(txnCode) : null);

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
        String baseUrlNormalized = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        String offerFetchUrl = String.format("%sv1/certify/credential-offer-data/%s", baseUrlNormalized, offerId);
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
}