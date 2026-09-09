package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.util.CommonUtil;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.AccessTokenJwtUtil;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class PreAuthorizedCodeService {

    private final VCICacheService vciCacheService;

    private final AccessTokenJwtUtil accessTokenJwtUtil;

    private final ObjectMapper objectMapper;

    private final CredentialConfigurationService credentialConfigurationService;

    private final CredentialConfigRepository credentialConfigRepository;

    private final Validator validator;

    @Value("${mosip.certify.identifier}")
    private String issuerIdentifier;

    @Value("${mosip.certify.pre-auth.default-expiry-seconds:600}")
    private int defaultExpirySeconds;

    @Value("${mosip.certify.pre-auth.min-expiry-seconds:60}")
    private int minExpirySeconds;

    @Value("${mosip.certify.pre-auth.max-expiry-seconds:86400}")
    private int maxExpirySeconds;

    @Value("${mosip.certify.credential-offer-url:}")
    private String credentialOfferUrl;

    @Value("${mosip.certify.oauth.token.expires-in-seconds:600}")
    private int accessTokenExpirySeconds;

    @Value("${mosip.certify.oauth.issuer:}")
    private String oauthIssuer;

    @Value("${mosip.certify.oauth.access-token.audience:}")
    private String oauthAudience;

    @Autowired
    public PreAuthorizedCodeService(VCICacheService vciCacheService,
                                    AccessTokenJwtUtil accessTokenJwtUtil,
                                    ObjectMapper objectMapper,
                                    CredentialConfigurationService credentialConfigurationService,
                                    CredentialConfigRepository credentialConfigRepository,
                                    Validator validator) {
        this.vciCacheService = vciCacheService;
        this.accessTokenJwtUtil = accessTokenJwtUtil;
        this.objectMapper = objectMapper;
        this.credentialConfigurationService = credentialConfigurationService;
        this.credentialConfigRepository = credentialConfigRepository;
        this.validator = validator;
    }
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    public String generatePreAuthorizedCode(PreAuthorizedRequest request) {
        validatePreAuthorizedRequest(request);
        int expirySeconds = request.getExpiresIn() != null ? request.getExpiresIn() : defaultExpirySeconds;
        if (expirySeconds < minExpirySeconds || expirySeconds > maxExpirySeconds) {
            log.error("expires_in {} out of bounds [{}, {}]", expirySeconds, minExpirySeconds, maxExpirySeconds);
            throw new InvalidRequestException(ErrorConstants.INVALID_EXPIRY_RANGE);
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

        return buildCredentialOfferUri(offerId);
    }

    private void validatePreAuthorizedRequest(PreAuthorizedRequest request) {
        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();
        Map<String, CredentialConfigurationSupportedDTO> supportedConfigs = metadata
                .getCredentialConfigurationSupportedDTO();

        if (supportedConfigs == null || !supportedConfigs.containsKey(request.getCredentialConfigurationId())) {
            log.error("Invalid credential configuration ID: {}", request.getCredentialConfigurationId());
            throw new InvalidRequestException(ErrorConstants.INVALID_CREDENTIAL_CONFIGURATION_ID);
        }

        CredentialConfigurationSupportedDTO config = supportedConfigs.get(request.getCredentialConfigurationId());
        validateClaims(config, request.getClaims());
    }

    private void validateClaims(CredentialConfigurationSupportedDTO config, Map<String, Object> providedClaims) {
        if (config.getCredentialMetadataDTO() == null ||
                config.getCredentialMetadataDTO().getClaims() == null) {
            return;
        }

        Set<String> allowedClaimKeys = new HashSet<>();
        List<String> mandatoryClaims = new ArrayList<>();

        for (CredentialMetadataDTO.Claims claim :
                config.getCredentialMetadataDTO().getClaims()) {

            List<String> path = claim.getPath();

            if (path != null && !path.isEmpty()) {
                String claimKey = path.getLast();

                allowedClaimKeys.add(claimKey);
                if (Boolean.TRUE.equals(claim.isMandatory())) {
                    mandatoryClaims.add(claimKey);
                }
            }
        }

        List<String> missingMandatoryClaims = mandatoryClaims.stream()
                .filter(key ->
                        !providedClaims.containsKey(key) ||
                                providedClaims.get(key) == null ||
                                providedClaims.get(key).toString().trim().isEmpty()
                )
                .toList();

        if (!missingMandatoryClaims.isEmpty()) {
            log.error("Missing mandatory claims: {}", missingMandatoryClaims);
            throw new InvalidRequestException(ErrorConstants.MISSING_MANDATORY_CLAIM);
        }

        List<String> unknownClaims = new ArrayList<>();
        for (String providedClaim : providedClaims.keySet()) {
            if (!allowedClaimKeys.contains(providedClaim)) {
                unknownClaims.add(providedClaim);
            }
        }
        if (!unknownClaims.isEmpty()) {
            log.error("Unknown claims provided: {}", unknownClaims);
            throw new InvalidRequestException(ErrorConstants.UNKNOWN_CLAIMS);
        }
    }

    public CredentialOfferResponse getCredentialOffer(String offerId) {
        log.info("Retrieving credential offer for ID: {}", offerId);

        // Trim offerId early to ensure validation and cache lookup use the same value
        if (offerId != null) {
            offerId = offerId.trim();
        }

        if (!isValidUUID(offerId)) {
            log.error("Invalid offer_id format: {}", offerId);
            throw new InvalidRequestException(ErrorConstants.INVALID_OFFER_ID_FORMAT);
        }

        CredentialOfferResponse offer = vciCacheService.getCredentialOffer(offerId);

        if (offer == null) {
            log.error("Credential offer not found or expired for ID: {}", offerId);
            throw new CertifyException(ErrorConstants.CREDENTIAL_OFFER_NOT_FOUND, "Credential offer not found or expired");
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
        Grant.PreAuthorizedCodeGrantType grant = Grant.PreAuthorizedCodeGrantType.builder()
                .preAuthorizedCode(preAuthCode)
                .txCode(StringUtils.hasText(txnCode) ? buildTxCodeInfo(txnCode) : null).build();

        Grant grants = Grant.builder().preAuthorizedCode(grant).build();

        return CredentialOfferResponse.builder()
                .credentialIssuer(issuerIdentifier)
                .credentialConfigurationIds(Collections.singletonList(configId))
                .grants(grants)
                .build();
    }

    private TxCode buildTxCodeInfo(String txnCode) {
        return TxCode.builder()
                .length(txnCode.length())
                .inputMode(txnCode.matches("\\d+") ? "numeric" : "text")
                .description("Please enter the transaction code provided to you")
                .build();
    }

    private String buildCredentialOfferUri(String offerId) {
        String offerFetchUrl = credentialOfferUrl + offerId;
        try {
            String encodedUrl = URLEncoder.encode(offerFetchUrl, StandardCharsets.UTF_8.name());
            return "openid-credential-offer://?credential_offer_uri=" + encodedUrl;
        } catch (java.io.UnsupportedEncodingException e) {
            // UTF-8 is always supported, this should never happen
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "UTF-8 encoding not supported", e);
        }
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
    public OAuthTokenResponse exchangePreAuthorizedCode(OAuthTokenRequest request) {
        Set<ConstraintViolation<OAuthTokenRequest>> violations =
                validator.validate(request);

        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }

        log.info("Processing token request for grant_type: {}", request.getGrant_type());

        // Retrieve and validate pre-auth code data
        PreAuthCodeData codeData = vciCacheService.getPreAuthCodeData(request.getPre_authorized_code());

        validateTokenRequest(request, codeData);

        // Generate access token
        String accessToken = generateAccessToken(codeData);

        long currentTime = System.currentTimeMillis();

        PreAuthTransaction transaction = new PreAuthTransaction();
        transaction.setCredentialConfigurationId(codeData.getCredentialConfigurationId());
        transaction.setClaims(codeData.getClaims());
        transaction.setCreatedAt(currentTime);

        vciCacheService.setPreAuthTransaction(CommonUtil.generateOIDCAtHash(accessToken), transaction);

        log.info("Successfully exchanged pre-authorized code for access token");

        OAuthTokenResponse response = new OAuthTokenResponse();
        response.setAccessToken(accessToken);
        response.setTokenType("Bearer");
        response.setExpiresIn(accessTokenExpirySeconds);
        return response;
    }

    private void validateTokenRequest(OAuthTokenRequest request, PreAuthCodeData codeData) {

        // Validate grant type
        if (!Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE.equals(request.getGrant_type())) {
            log.error("Unsupported grant type: {}", request.getGrant_type());
            throw new CertifyException(ErrorConstants.UNSUPPORTED_GRANT_TYPE, "Grant type not supported");
        }

        // Reject unknown codes immediately before any expiry or claim check
        if (codeData == null) {
            log.error("Pre-authorized code not found");
            throw new CertifyException(ErrorConstants.INVALID_GRANT, "Pre-authorized code not found");
        }

        // Atomically validate expiry and claim to avoid TOCTOU around expiry boundary
        long currentTime = System.currentTimeMillis();
        VCICacheService.PreAuthCodeClaimResult claimResult =
                vciCacheService.claimPreAuthCodeIfUnexpired(request.getPre_authorized_code(), currentTime);
        if (claimResult == VCICacheService.PreAuthCodeClaimResult.EXPIRED) {
            log.error("Pre-authorized code expired. Expiry: {}, Current: {}", codeData.getExpiresAt(), currentTime);
            throw new CertifyException("pre_auth_code_expired", "Pre-authorized code has expired");
        }
        if (claimResult == VCICacheService.PreAuthCodeClaimResult.INVALID_OR_USED) {
            log.error("Pre-authorized code already used or invalid");
            throw new CertifyException(ErrorConstants.INVALID_GRANT, "Pre-authorized code has already been used  or invalid");
        }

        // Validate transaction code if required
        String expectedTxCode = codeData.getTxnCode();
        if (StringUtils.hasText(expectedTxCode) && !StringUtils.hasText(request.getTx_code())) {
            log.error("Transaction code required but not provided");
            throw new CertifyException("tx_code_required", "Transaction code is required for this pre-authorized code");
        }
        if (StringUtils.hasText(expectedTxCode) && !expectedTxCode.equals(request.getTx_code())) {
            log.error("Transaction code mismatch");
            throw new CertifyException("tx_code_mismatch", "Transaction code does not match");
        }
    }

    /**
     * Generate a signed JWT access token for pre-authorized code flow.
     * Calls AccessTokenJwtUtil.generateSignedJwt directly with raw parameters.
     */
    private String generateAccessToken(PreAuthCodeData codeData) {
        try {
            String claimsJson = objectMapper.writeValueAsString(codeData.getClaims());
            String credentialConfigId = codeData.getCredentialConfigurationId();

            // Lookup credential configuration in database
            String credentialScope = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigId)
                    .map(credentialConfig -> {
                        if (!Constants.ACTIVE.equals(credentialConfig.getStatus())) {
                            log.error("Credential configuration is not active for ID: {}, status: {}",
                                    credentialConfigId, credentialConfig.getStatus());
                            throw new CertifyException("invalid_request",
                                    "Credential configuration is not active: " + credentialConfigId);
                        }
                        String scope = credentialConfig.getScope();
                        if (!StringUtils.hasText(scope)) {
                            log.error("Scope is not configured for credential configuration ID: {}", credentialConfigId);
                            throw new CertifyException("server_error",
                                    "Scope not configured for credential: " + credentialConfigId);
                        }
                        return scope;
                    })
                    .orElseThrow(() -> {
                        log.error("Credential configuration not found for ID: {}", credentialConfigId);
                        return new CertifyException("invalid_request",
                                "Invalid credential_configuration_id: " + credentialConfigId);
                    });

            return accessTokenJwtUtil.generateSignedJwt(
                    claimsJson,
                    credentialScope,
                    "",
                    oauthIssuer,
                    oauthAudience,
                    accessTokenExpirySeconds
            );
        } catch (Exception e) {
            log.error("Failed to generate access token for pre-authorized code flow", e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Failed to generate access token", e);
        }
    }
}