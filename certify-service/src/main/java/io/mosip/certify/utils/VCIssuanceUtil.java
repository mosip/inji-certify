package io.mosip.certify.utils;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.services.VCICacheService;
import io.mosip.certify.api.dto.VCResult;

import org.slf4j.Logger;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

public class VCIssuanceUtil {

    private VCIssuanceUtil() {
        // Private constructor to prevent instantiation
    }

    public static Map<String, Object> convertLatestToVd12(LinkedHashMap<String, Object> vciMetadata) {
        // Create a new map to store the transformed configuration
        if(vciMetadata.containsKey("credential_configurations_supported")) {
            LinkedHashMap<String, Object> supportedCredentials = (LinkedHashMap<String, Object>) vciMetadata.get("credential_configurations_supported");
            Map<String, Object> transformedMap = transformCredentialConfiguration(supportedCredentials);
            vciMetadata.put("credentials_supported", transformedMap);
        }

        vciMetadata.remove("credential_configurations_supported");
        String endpoint = (String)vciMetadata.get("credential_endpoint");
        int issuanceIndex = endpoint.indexOf("issuance/");
        String newEndPoint = endpoint.substring(0, issuanceIndex+9);
        vciMetadata.put("credential_endpoint", newEndPoint + "vd12/credential");
        return vciMetadata;
    }

    public static Map<String, Object> convertLatestToVd11(LinkedHashMap<String, Object> vciMetadata) {
        // Create a list to hold the transformed credentials
        List<Map<String, Object>> credentialsList = new ArrayList<>();

        // Check if the original config contains 'credential_configurations_supported'
        if (vciMetadata.containsKey("credential_configurations_supported")) {
            // Cast the value to a Map
            Map<String, Object> originalCredentials =
                    (Map<String, Object>) vciMetadata.get("credential_configurations_supported");

            // Iterate through each credential
            for (Map.Entry<String, Object> entry : originalCredentials.entrySet()) {
                // Cast the credential configuration
                Map<String, Object> credConfig = (Map<String, Object>) entry.getValue();

                // Create a new transformed credential configuration
                Map<String, Object> transformedCredential = new HashMap<>(credConfig);

                // Add 'id' field with the original key
                transformedCredential.put("id", entry.getKey());

                // Rename 'credential_signing_alg_values_supported' to 'cryptographic_suites_supported'
                if (transformedCredential.containsKey("credential_signing_alg_values_supported")) {
                    transformedCredential.put("cryptographic_suites_supported",
                            transformedCredential.remove("credential_signing_alg_values_supported"));
                }

                // Modify proof_types_supported
                if (transformedCredential.containsKey("proof_types_supported")) {
                    Map<String, Object> proofTypes = (Map<String, Object>) transformedCredential.get("proof_types_supported");
                    transformedCredential.put("proof_types_supported", proofTypes.keySet());
                }

                if(transformedCredential.containsKey("display")) {
                    List<Map<String, Object>> displayMapList = new ArrayList<>((List<Map<String, Object>>)transformedCredential.get("display"));
                    List<Map<String, Object>> newDisplayMapList = new ArrayList<>();
                    for(Map<String, Object> map : displayMapList) {
                        Map<String, Object> displayMap = new HashMap<>(map);
                        displayMap.remove("background_image");
                        newDisplayMapList.add(displayMap);
                    }
                    transformedCredential.put("display", newDisplayMapList);
                }

                // Remove 'order' if it exists
                transformedCredential.remove("order");

                // Add the transformed credential to the list
                credentialsList.add(transformedCredential);
            }

            // Set the transformed credentials in the new configuration
            vciMetadata.put("credentials_supported", credentialsList);
        }

        vciMetadata.remove("credential_configurations_supported");
        vciMetadata.remove("authorization_servers");
        vciMetadata.remove("display");
        String endpoint = (String)vciMetadata.get("credential_endpoint");
        int issuanceIndex = endpoint.indexOf("issuance/");
        String newEndPoint = endpoint.substring(0, issuanceIndex+9);
        vciMetadata.put("credential_endpoint", newEndPoint + "vd11/credential");
        return vciMetadata;
    }

    public static Map<String, Object> transformCredentialConfiguration(LinkedHashMap<String, Object> originalConfig) {
        Map<String, Object> transformedConfig = new LinkedHashMap<>();

        for (Map.Entry<String, Object> entry : originalConfig.entrySet()) {
            Map<String, Object> credentialDetails = (Map<String, Object>) entry.getValue();

            // Create a new map to store modified credential details
            Map<String, Object> transformedCredential = new LinkedHashMap<>(credentialDetails);

            // Replace 'credential_signing_alg_values_supported' with 'cryptographic_suites_supported'
            if (transformedCredential.containsKey("credential_signing_alg_values_supported")) {
                Object signingAlgs = transformedCredential.remove("credential_signing_alg_values_supported");
                transformedCredential.put("cryptographic_suites_supported", signingAlgs);
            }

            // Modify proof_types_supported
            if (transformedCredential.containsKey("proof_types_supported")) {
                Map<String, Object> proofTypes = (Map<String, Object>) transformedCredential.get("proof_types_supported");
                transformedCredential.put("proof_types_supported", proofTypes.keySet());
            }

            if(transformedCredential.containsKey("display")) {
                List<Map<String, Object>> displayMapList = new ArrayList<>((List<Map<String, Object>>)transformedCredential.get("display"));
                List<Map<String, Object>> newDisplayMapList = new ArrayList<>();
                for(Map<String, Object> map : displayMapList) {
                    Map<String, Object> displayMap = new HashMap<>(map);
                    displayMap.remove("background_image");
                    newDisplayMapList.add(displayMap);
                }
                transformedCredential.put("display", newDisplayMapList);
            }

            // Add the modified credential details to the transformed config
            transformedConfig.put(entry.getKey(), transformedCredential);
        }

        return transformedConfig;
    }

    public static String getValidClientNonce(VCICacheService vciCacheService, ParsedAccessToken parsedAccessToken,
                                             int configuredCNonceExpireSeconds, SecurityHelperService securityHelperService, Logger log) {
        VCIssuanceTransaction transaction = vciCacheService.getVCITransaction(parsedAccessToken.getAccessTokenHash());
        String cNonce = (transaction == null) ?
                (String) parsedAccessToken.getClaims().get(Constants.C_NONCE) :
                transaction.getCNonce();

        Object nonceExpireSecondsClaim = parsedAccessToken.getClaims().getOrDefault(Constants.C_NONCE_EXPIRES_IN, 0);
        int cNonceExpire = (transaction == null) ?
                determineCNonceExpiry(nonceExpireSecondsClaim) :
                transaction.getCNonceExpireSeconds();

        long issuedEpoch;
        if (transaction == null) {
            Object iatClaimValue = parsedAccessToken.getClaims().get(JwtClaimNames.IAT);
            if (iatClaimValue == null) {
                issuedEpoch = Instant.MIN.getEpochSecond();
            } else if (iatClaimValue instanceof Instant) {
                issuedEpoch = ((Instant) iatClaimValue).getEpochSecond();
            } else if (iatClaimValue instanceof Number) {
                issuedEpoch = ((Number) iatClaimValue).longValue();
            } else {
                throw new IllegalStateException("IAT claim is of an unexpected type: " + iatClaimValue.getClass().getName());
            }
        } else {
            issuedEpoch = transaction.getCNonceIssuedEpoch();
        }

        if (cNonce == null ||
                cNonceExpire <= 0 ||
                (issuedEpoch + cNonceExpire) < LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC)) {
            String accessTokenHash = parsedAccessToken.getAccessTokenHash();
            log.error("Client Nonce not found / expired in the access token, generate new cNonce for accessTokenHash: {}",
                    accessTokenHash != null ? accessTokenHash.substring(0, Math.min(accessTokenHash.length(), 10)) + "..." : "null");
            VCIssuanceTransaction newTransaction = createVCITransaction(securityHelperService, configuredCNonceExpireSeconds, vciCacheService, accessTokenHash);
            throw new InvalidNonceException(newTransaction.getCNonce(), newTransaction.getCNonceExpireSeconds());
        }
        return cNonce;
    }

    public static int determineCNonceExpiry(Object nonceExpireSecondsClaim) {
        if (nonceExpireSecondsClaim instanceof Long) {
            return (int)(long)nonceExpireSecondsClaim;
        } else if (nonceExpireSecondsClaim instanceof Integer) {
            return (int)nonceExpireSecondsClaim;
        }
        return 0;
    }

    public static VCIssuanceTransaction createVCITransaction(SecurityHelperService securityHelperService, int cNonceExpireSecondsConfig,
                                                             VCICacheService vciCacheService, String accessTokenHash) {
        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce(securityHelperService.generateSecureRandomString(20));
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));
        transaction.setCNonceExpireSeconds(cNonceExpireSecondsConfig);
        return vciCacheService.setVCITransaction(accessTokenHash, transaction);
    }

    @SuppressWarnings("unchecked")
    public static CredentialResponse<?> getCredentialResponse(String format, VCResult<?> vcResult) {
        switch (format) {
            case VCFormats.LDP_VC:
                CredentialResponse<JsonLDObject> ldpVcResponse = new CredentialResponse<>();
                ldpVcResponse.setCredential((JsonLDObject) vcResult.getCredential());
                return ldpVcResponse;

            case VCFormats.LDP_SD_JWT:
            case VCFormats.JWT_VC_JSON:
            case VCFormats.JWT_VC_JSON_LD:
            case VCFormats.MSO_MDOC:
                CredentialResponse<String> stringResponse = new CredentialResponse<>();
                stringResponse.setCredential((String) vcResult.getCredential());
                return stringResponse;

            default:
                throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT, " Input format " + format);
        }
    }

    public static Optional<CredentialMetadata> getScopeCredentialMapping(String scope, String format, CredentialIssuerMetadataDTO credentialIssuerMetadataDTO) {

        Map<String, CredentialConfigurationSupportedDTO> supportedCredentials = credentialIssuerMetadataDTO.getCredentialConfigurationSupportedDTO();
        Optional<Map.Entry<String, CredentialConfigurationSupportedDTO>> result = supportedCredentials.entrySet().stream()
                .filter(cm -> cm.getValue().getScope().equals(scope)).findFirst();

        if(result.isPresent()) {
            CredentialConfigurationSupportedDTO metadata = result.get().getValue();
            CredentialMetadata credentialMetadata = new CredentialMetadata();
            credentialMetadata.setFormat(metadata.getFormat());
            credentialMetadata.setScope(metadata.getScope());
            credentialMetadata.setId(result.get().getKey());
            if(format.equals(VCFormats.LDP_VC)){
                credentialMetadata.setTypes(metadata.getCredentialDefinition().getType());
            }
            return Optional.of(credentialMetadata);
        }
        return Optional.empty();
    }

    public static void validateLdpVcFormatRequest(CredentialRequest credentialRequest,
                                                  CredentialMetadata credentialMetadata) {
        if(!credentialRequest.getCredential_definition().getType().containsAll(credentialMetadata.getTypes()))
            throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_VC_TYPE);

        //TODO need to validate Credential_definition as JsonLD document, if invalid throw exception
    }

    public static void validateSdJwtVcFormatRequest(CredentialRequest credentialRequest) {
        if(credentialRequest.getVct() == null)
            throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_VC_TYPE);

    }
}