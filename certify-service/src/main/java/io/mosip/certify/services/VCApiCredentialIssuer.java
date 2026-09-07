package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCDMConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.utils.LedgerUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Slf4j
@Component
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiCredentialIssuer {

    private static final String CONTEXT = "@context";
    private static final String ISSUER = "issuer";
    private static final String CREDENTIAL_SUBJECT = "credentialSubject";

    @Autowired
    private CredentialFactory credentialFactory;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Autowired
    private CredentialLedgerService credentialLedgerService;

    @Autowired
    private LedgerUtils ledgerUtils;

    @Value("#{${mosip.certify.issuer.ledger-enabled:true}}")
    private boolean isLedgerEnabled;

    @Value("${mosip.certify.data-provider-plugin.vc-expiry-duration:P730D}")
    private String defaultExpiryDuration;

    public VCApiIssueResult issueValidatedCredential(Map<String, Object> credential,
                                                     CredentialConfigurationDTO config) {
        validateNoProof(credential);
        validateFormat(config);
        validateVcdm2AndMatchConfig(credential, config);
        validateAgainstVcTemplate(credential, config);

        JSONObject jsonObject = new JSONObject(credential);
        // Apply/validate validFrom and validUntil before status-list / ledger / signing.
        LocalDateTime issuanceDate = applyValidityPeriod(jsonObject);

        // Status is required for VC API so issued credentials are revocable.
        // Index is claimed before signing because credentialStatus is part of the signed payload.
        addCredentialStatus(jsonObject, config);

        try {
            Credential cred = credentialFactory.getCredential(VCFormats.LDP_VC)
                    .orElseThrow(() -> new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT));

            String didUrl = requireNonBlank(config.getDidUrl(), "didUrl");
            String appId = requireNonBlank(config.getKeyManagerAppId(), "keyManagerAppId");
            String refId = config.getKeyManagerRefId() != null ? config.getKeyManagerRefId() : "";
            String signAlgorithm = requireNonBlank(config.getSignatureAlgo(), "signatureAlgo");
            String cryptoSuite = requireNonBlank(config.getSignatureCryptoSuite(), "signatureCryptoSuite");

            String unsignedCredential = jsonObject.toString();
            VCResult<?> result = cred.addProof(unsignedCredential, "", signAlgorithm, appId, refId, didUrl, cryptoSuite);
            if (result == null || !(result.getCredential() instanceof JsonLDObject signedCredential)) {
                throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED,
                        "Credential signing did not return a signed credential");
            }

            // Persist ledger only after a valid signed credential exists.
            if (isLedgerEnabled) {
                storeLedger(jsonObject, config, issuanceDate);
            }
            return new VCApiIssueResult(signedCredential);
        } catch (JSONException e) {
            log.error("VC API credential signing failed: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Invalid JSON data encountered during credential issuance");
        }
    }

    private void validateNoProof(Map<String, Object> credential) {
        if (credential.containsKey(VCDMConstants.PROOF)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Credential must not include an existing proof");
        }
    }

    private void validateFormat(CredentialConfigurationDTO config) {
        if (!VCFormats.LDP_VC.equals(config.getCredentialFormat())) {
            throw new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT,
                    "VC API supports only ldp_vc credential format");
        }
    }

    private void validateVcdm2AndMatchConfig(Map<String, Object> credential, CredentialConfigurationDTO config) {
        List<String> requestContexts = toStringList(credential.get(CONTEXT), CONTEXT);
        if (!requestContexts.contains(VCDM2Constants.URL)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Credential @context must include VCDM 2.0 URL: " + VCDM2Constants.URL);
        }

        List<String> configContexts = config.getContextURLs() != null ? config.getContextURLs() : List.of();
        if (!sameStringSet(requestContexts, configContexts)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Credential @context does not match onboarded credential configuration");
        }

        List<String> requestTypes = toStringList(credential.get(Constants.TYPE), Constants.TYPE);
        List<String> configTypes = config.getCredentialTypes() != null ? config.getCredentialTypes() : List.of();
        if (configTypes.isEmpty() || !sameStringSet(requestTypes, configTypes)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Credential type does not match onboarded credential configuration");
        }

        String requestIssuer = extractIssuerId(credential.get(ISSUER));
        String configIssuer = config.getDidUrl();
        if (StringUtils.isBlank(configIssuer) || !Objects.equals(requestIssuer, configIssuer)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Credential issuer does not match onboarded credential configuration");
        }
    }

    /**
     * Validates request {@code credentialSubject} against the onboarded {@code vcTemplate}.
     * Request subject keys must include every template subject key. Extra keys are rejected,
     * except JSON-LD {@code id} ({@code @id}), which is an optional subject identifier and
     * may be present even when omitted from the Velocity template.
     */
    private void validateAgainstVcTemplate(Map<String, Object> credential, CredentialConfigurationDTO config) {
        JSONObject template = parseVcTemplate(config.getVcTemplate());
        if (!template.has(CREDENTIAL_SUBJECT) || !(template.get(CREDENTIAL_SUBJECT) instanceof JSONObject)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Onboarded vcTemplate must define credentialSubject for W3C VC API validation");
        }

        JSONObject templateSubject = template.getJSONObject(CREDENTIAL_SUBJECT);
        Set<String> expectedKeys = new HashSet<>(templateSubject.keySet());
        if (expectedKeys.isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Onboarded vcTemplate credentialSubject must define at least one field");
        }

        Object requestSubjectObj = credential.get(CREDENTIAL_SUBJECT);
        if (!(requestSubjectObj instanceof Map<?, ?> requestSubject) || requestSubject.isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Missing or empty credentialSubject");
        }

        Set<String> requestKeys = new HashSet<>();
        for (Object key : requestSubject.keySet()) {
            if (key != null) {
                requestKeys.add(key.toString());
            }
        }

        Set<String> missing = new HashSet<>(expectedKeys);
        missing.removeAll(requestKeys);
        if (!missing.isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "credentialSubject is missing fields required by onboarded vcTemplate: " + missing);
        }

        Set<String> unexpected = new HashSet<>(requestKeys);
        unexpected.removeAll(expectedKeys);
        // JSON-LD subject identifier (@id) is allowed even when not present in Velocity template.
        unexpected.remove(VCDMConstants.ID);
        if (!unexpected.isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "credentialSubject has fields not defined in onboarded vcTemplate: " + unexpected);
        }
    }

    private JSONObject parseVcTemplate(String vcTemplate) {
        if (StringUtils.isBlank(vcTemplate)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Onboarded credential configuration is missing vcTemplate required for W3C VC API validation");
        }
        String trimmed = vcTemplate.trim();
        try {
            if (trimmed.startsWith("{")) {
                return new JSONObject(trimmed);
            }
            String decoded = new String(Base64.decodeBase64(trimmed), StandardCharsets.UTF_8).trim();
            if (!decoded.startsWith("{")) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                        "Onboarded vcTemplate is not valid JSON");
            }
            return new JSONObject(decoded);
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Unable to parse onboarded vcTemplate: " + e.getMessage());
        }
    }

    private boolean sameStringSet(List<String> left, List<String> right) {
        return new HashSet<>(left).equals(new HashSet<>(right));
    }

    @SuppressWarnings("unchecked")
    private List<String> toStringList(Object value, String fieldName) {
        if (value == null) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Missing required field: " + fieldName);
        }
        if (value instanceof String s) {
            return List.of(s);
        }
        if (value instanceof Collection<?> collection) {
            List<String> result = new ArrayList<>();
            for (Object item : collection) {
                if (item == null) {
                    continue;
                }
                result.add(item.toString());
            }
            if (result.isEmpty()) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Empty required field: " + fieldName);
            }
            return result;
        }
        throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Invalid type for field: " + fieldName);
    }

    @SuppressWarnings("unchecked")
    private String extractIssuerId(Object issuer) {
        if (issuer == null) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Missing required field: issuer");
        }
        if (issuer instanceof String s) {
            if (StringUtils.isBlank(s)) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Blank issuer");
            }
            return s.trim();
        }
        if (issuer instanceof Map<?, ?> map) {
            Object id = map.get("id");
            if (id == null || StringUtils.isBlank(id.toString())) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST, "issuer.id is required when issuer is an object");
            }
            return id.toString().trim();
        }
        throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Invalid issuer format");
    }

    /**
     * Allocates a BitstringStatusList entry. Mandatory for VC API issuance so credentials
     * can be revoked/suspended via Certify status APIs.
     */
    private void addCredentialStatus(JSONObject jsonObject, CredentialConfigurationDTO config) {
        List<String> purposes = config.getCredentialStatusPurposes();
        if (purposes == null || purposes.isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "credentialStatusPurposes is required for VC API issuance (revocation support)");
        }
        if (!isLedgerEnabled) {
            log.warn("Ledger feature is disabled while revocation is enabled for config {}",
                    config.getCredentialConfigKeyId());
        }
        statusListCredentialService.addCredentialStatus(jsonObject, purposes.getFirst());
    }

    /**
     * VCDM 2.0 treats {@code validFrom} / {@code validUntil} as optional, but if
     * {@code validUntil} is present then {@code validFrom} MUST exist and
     * {@code validUntil} MUST be later. Callers may omit either field; omitted
     * {@code validFrom} is set to now, omitted {@code validUntil} is set to
     * {@code validFrom} plus {@code mosip.certify.data-provider-plugin.vc-expiry-duration}.
     */
    private LocalDateTime applyValidityPeriod(JSONObject jsonObject) {
        String validFromRaw = optionalDateString(jsonObject, VCDM2Constants.VALID_FROM);
        LocalDateTime validFromTime;
        if (validFromRaw == null) {
            validFromTime = ZonedDateTime.now(ZoneOffset.UTC).toLocalDateTime();
            jsonObject.put(VCDM2Constants.VALID_FROM, formatUtc(validFromTime));
        } else {
            validFromTime = parseValidityDateTime(validFromRaw, VCDM2Constants.VALID_FROM);
        }

        String validUntilRaw = optionalDateString(jsonObject, VCDM2Constants.VALID_UNTIL);
        if (validUntilRaw == null) {
            LocalDateTime validUntilTime = validFromTime.plus(parseExpiryDuration());
            jsonObject.put(VCDM2Constants.VALID_UNTIL, formatUtc(validUntilTime));
        } else {
            LocalDateTime validUntilTime = parseValidityDateTime(validUntilRaw, VCDM2Constants.VALID_UNTIL);
            if (!validUntilTime.isAfter(validFromTime)) {
                throw new CertifyException(ErrorConstants.INVALID_EXPIRY_RANGE,
                        "validUntil must be later than validFrom");
            }
        }
        return validFromTime;
    }

    private String optionalDateString(JSONObject jsonObject, String field) {
        if (!jsonObject.has(field) || jsonObject.isNull(field)) {
            return null;
        }
        String value = jsonObject.optString(field, "").trim();
        return StringUtils.isBlank(value) ? null : value;
    }

    private Duration parseExpiryDuration() {
        try {
            return Duration.parse(defaultExpiryDuration);
        } catch (DateTimeParseException | NullPointerException e) {
            log.warn("Incorrect expiry duration format in properties: {}. Using default P730D ~ 2Y",
                    defaultExpiryDuration);
            return Duration.parse("P730D");
        }
    }

    private String formatUtc(LocalDateTime time) {
        return time.atZone(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
    }

    private void storeLedger(JSONObject jsonObject, CredentialConfigurationDTO config, LocalDateTime issuanceDate) {
        Map<String, Object> indexedAttributes = ledgerUtils.extractIndexedAttributes(jsonObject);
        String credentialType = LedgerUtils.extractCredentialType(jsonObject);
        String credentialId = jsonObject.has("id") ? jsonObject.optString("id", null) : null;
        if (StringUtils.isBlank(credentialId)) {
            credentialId = null;
        }
        CredentialStatusDetail credentialStatusDetail = ledgerUtils.extractCredentialStatusDetails(jsonObject);
        credentialLedgerService.storeLedgerEntry(credentialId, config.getDidUrl(), credentialType,
                credentialStatusDetail, indexedAttributes, issuanceDate);
        log.info("VC API ledger entry stored for credentialType: {}", credentialType);
    }

    private LocalDateTime parseValidityDateTime(String time, String fieldName) {
        try {
            return LocalDateTime.parse(time, DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        } catch (Exception first) {
            try {
                // Accept common VCDM ISO-8601 forms (with/without millis, with Z offset).
                return java.time.Instant.parse(normalizeToInstant(time)).atZone(ZoneOffset.UTC).toLocalDateTime();
            } catch (Exception second) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                        "Invalid " + fieldName + "; expected UTC pattern " + Constants.UTC_DATETIME_PATTERN
                                + " (e.g. 2026-01-01T00:00:00.000Z)");
            }
        }
    }

    private String normalizeToInstant(String time) {
        if (time.endsWith("Z") || time.contains("+") || time.matches(".*[+-]\\d{2}:\\d{2}$")) {
            return time;
        }
        return time + "Z";
    }

    private String requireNonBlank(String value, String fieldName) {
        if (StringUtils.isBlank(value)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST,
                    "Credential configuration missing required signing field: " + fieldName);
        }
        return value;
    }

    public record VCApiIssueResult(JsonLDObject verifiableCredential) {
    }
}
