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
    private VCICacheService vciCacheService;

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
        log.info("Generating pre-authorized code for credential configuration: {}", request.getCredentialConfigurationId());

        validatePreAuthorizedRequest(request);

        int expirySeconds = request.getExpiresIn() != null ? request.getExpiresIn() : defaultExpirySeconds;

        if (expirySeconds < minExpirySeconds || expirySeconds > maxExpirySeconds) {
            log.error("expires_in {} out of bounds [{}, {}]", expirySeconds, minExpirySeconds, maxExpirySeconds);
            throw new InvalidRequestException(String.format("expires_in must be between %d and %d seconds", minExpirySeconds, maxExpirySeconds));
        }

        String offerId = UUID.randomUUID().toString();
        String preAuthCode = generateUniquePreAuthCode();

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
        Map<String, Object> supportedConfigs = (Map<String, Object>) metadata.get(Constants.CREDENTIAL_CONFIGURATIONS_SUPPORTED);

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
                    String.format("Missing mandatory claims: %s", String.join(", ", missingClaims))
            );
        }

        if (!unknownClaims.isEmpty()) {
            log.error("Unknown claims provided: {}", unknownClaims);
            throw new InvalidRequestException(
                    String.format("Unknown claims: %s", String.join(", ", unknownClaims))
            );
        }
    }


    private String generateUniquePreAuthCode() {
        String preAuthCode;
        int attempts = 0;
        final int MAX_ATTEMPTS = 3;

        do {
            preAuthCode = generateSecureCode(32);
            attempts++;
        } while (vciCacheService.getPreAuthCodeData(preAuthCode) != null && attempts < MAX_ATTEMPTS);

        if (vciCacheService.getPreAuthCodeData(preAuthCode) != null) {
            throw new IllegalStateException("Failed to generate unique pre-authorized code after " + MAX_ATTEMPTS + " attempts");
        }

        return preAuthCode;
    }

    private CredentialOfferResponse buildCredentialOffer(String configId, String preAuthCode, String txnCode) {
        Grant.PreAuthorizedCodeGrant grant = Grant.PreAuthorizedCodeGrant.builder()
                .preAuthorizedCode(preAuthCode)
                .txCode(StringUtils.hasText(txnCode) ? buildTxCodeInfo(txnCode) : null).build();

        Grant grants = Grant.builder().preAuthorizedCode(grant).build();

        return CredentialOfferResponse.builder()
                .credentialIssuer(issuerIdentifier)
                .credentialConfigurationIds(Collections.singletonList(configId))
                .grants(grants).build();
    }

    private TxCode buildTxCodeInfo(String txnCode) {
        return TxCode.builder()
                .length(txnCode.length())
                .inputMode(txnCode.matches("\\d+") ? "numeric" : "text")
                .description("Please enter the transaction code provided to you")
                .build();
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
}