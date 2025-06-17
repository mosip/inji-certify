/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.*;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.config.IndexedAttributesConfig;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialMetadata;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.core.util.AuditHelper;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.certify.validators.CredentialRequestValidator;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.CredentialUtils;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.vcsigners.VCSigner;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.*;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "DataProvider")
public class CertifyIssuanceServiceImpl implements VCIssuanceService {

    public static final Map<String, List<String>> keyChooser = Map.of(
            SignatureAlg.RSA_SIGNATURE_SUITE_2018, List.of(Constants.CERTIFY_VC_SIGN_RSA, Constants.EMPTY_REF_ID),
            SignatureAlg.ED25519_SIGNATURE_SUITE_2018, List.of(Constants.CERTIFY_VC_SIGN_ED25519, Constants.ED25519_REF_ID),
            SignatureAlg.ED25519_SIGNATURE_SUITE_2020, List.of(Constants.CERTIFY_VC_SIGN_ED25519, Constants.ED25519_REF_ID),
            SignatureAlg.EC_K1_2016, List.of(Constants.CERTIFY_VC_SIGN_EC_K1, Constants.EC_SECP256K1_SIGN),
            SignatureAlg.EC_SECP256K1_2019, List.of(Constants.CERTIFY_VC_SIGN_EC_K1, Constants.EC_SECP256K1_SIGN));
    @Value("${mosip.certify.data-provider-plugin.issuer.vc-sign-algo:Ed25519Signature2020}")
    private String vcSignAlgorithm;
    @Value("#{${mosip.certify.key-values}}")
    private LinkedHashMap<String, LinkedHashMap<String, Object>> issuerMetadata;

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpireSeconds;

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Autowired
    private VCFormatter vcFormatter;

    @Autowired
    private VCSigner vcSigner;

    @Autowired
    private DataProviderPlugin dataProviderPlugin;

    @Value("${mosip.certify.data-provider-plugin.issuer-uri}")
    private String issuerURI;

    @Value("${mosip.certify.data-provider-plugin.issuer-public-key-uri}")
    private String issuerPublicKeyURI;

    @Value("${mosip.certify.data-provider-plugin.rendering-template-id:}")
    private String renderTemplateId;

    @Autowired
    private ProofValidatorFactory proofValidatorFactory;

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private SecurityHelperService securityHelperService;

    @Autowired
    private AuditPlugin auditWrapper;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    private LedgerRepository ledgerRepository;

    @Autowired
    private IndexedAttributesConfig indexedAttributesConfig;

    @Value("${mosip.certify.statuslist.enabled:true}")
    private boolean statusListEnabled;

    @Value("${mosip.certify.statuslist.default-purpose:revocation}")
    private String defaultStatusPurpose;

    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    private Map<String, Object> didDocument;

    @Override
    public CredentialResponse getCredential(CredentialRequest credentialRequest) {
        // 1. Credential Request validation
        boolean isValidCredentialRequest = CredentialRequestValidator.isValid(credentialRequest);
        if(!isValidCredentialRequest) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if(!parsedAccessToken.isActive())
            throw new NotAuthenticatedException();
        // 2. Scope Validation
        String scopeClaim = (String) parsedAccessToken.getClaims().getOrDefault("scope", "");
        CredentialMetadata credentialMetadata = null;
        for(String scope : scopeClaim.split(Constants.SPACE)) {
            Optional<CredentialMetadata> result = getScopeCredentialMapping(scope, credentialRequest.getFormat());
            if(result.isPresent()) {
                credentialMetadata = result.get(); //considering only first credential scope
                break;
            }
        }

        if(credentialMetadata == null) {
            log.error("No credential mapping found for the provided scope {}", scopeClaim);
            throw new CertifyException(ErrorConstants.INVALID_SCOPE);
        }

        // 3. Proof Validation
        ProofValidator proofValidator = proofValidatorFactory.getProofValidator(credentialRequest.getProof().getProof_type());
        if(!proofValidator.validate((String)parsedAccessToken.getClaims().get(Constants.CLIENT_ID), getValidClientNonce(),
                credentialRequest.getProof())) {
            throw new CertifyException(ErrorConstants.INVALID_PROOF);
        }

        // 4. Get VC from configured plugin implementation
        VCResult<?> vcResult = getVerifiableCredential(credentialRequest, credentialMetadata,
                proofValidator.getKeyMaterial(credentialRequest.getProof()));

        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        return getCredentialResponse(credentialRequest.getFormat(), vcResult);
    }

    @Override
    public Map<String, Object> getCredentialIssuerMetadata(String version) {
        if(issuerMetadata.containsKey(version)) {
            return issuerMetadata.get(version);
        } else if(version != null && version.equals("vd12")) {
            LinkedHashMap<String, Object> originalIssuerMetadata = new LinkedHashMap<>(issuerMetadata.get("latest"));
            Map<String, Object> vd12IssuerMetadata = convertLatestToVd12(originalIssuerMetadata);
            issuerMetadata.put("vd12", (LinkedHashMap<String, Object>) vd12IssuerMetadata);
            return vd12IssuerMetadata;
        } else if(version != null && version.equals("vd11")) {
            LinkedHashMap<String, Object> originalIssuerMetadata = new LinkedHashMap<>(issuerMetadata.get("latest"));
            Map<String, Object> vd11IssuerMetadata = convertLatestToVd11(originalIssuerMetadata);
            issuerMetadata.put("vd11", (LinkedHashMap<String, Object>) vd11IssuerMetadata);
            return vd11IssuerMetadata;
        }
        throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_OPENID_VERSION);
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        if(didDocument != null)
            return didDocument;

        KeyPairGenerateResponseDto keyPairGenerateResponseDto = keymanagerService.getCertificate(keyChooser.get(vcSignAlgorithm).getFirst(), Optional.of(keyChooser.get(vcSignAlgorithm).getLast()));
        String certificateString = keyPairGenerateResponseDto.getCertificate();

        didDocument = DIDDocumentUtil.generateDIDDocument(vcSignAlgorithm, certificateString, issuerURI, issuerPublicKeyURI);
        return didDocument;
    }

    private Map<String, Object> convertLatestToVd11(LinkedHashMap<String, Object> vciMetadata) {
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

    private Map<String, Object> convertLatestToVd12(LinkedHashMap<String, Object> vciMetadata) {
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

    private static Map<String, Object> transformCredentialConfiguration(LinkedHashMap<String, Object> originalConfig) {
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

    @Transactional
    private VCResult<?> getVerifiableCredential(CredentialRequest credentialRequest, CredentialMetadata credentialMetadata,
                                                String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialRequest.getFormat());


        VCResult<?> vcResult = null;
        switch (credentialRequest.getFormat()) {
            case "ldp_vc" :
                vcRequestDto.setContext(credentialRequest.getCredential_definition().getContext());
                vcRequestDto.setType(credentialRequest.getCredential_definition().getType());
                vcRequestDto.setCredentialSubject(credentialRequest.getCredential_definition().getCredentialSubject());
                validateLdpVcFormatRequest(credentialRequest, credentialMetadata);
                try {
                    // TODO(multitenancy): later decide which plugin out of n plugins is the correct one
                    JSONObject jsonObject = dataProviderPlugin.fetchData(parsedAccessToken.getClaims());
                    Map<String, Object> templateParams = new HashMap<>();
                    templateParams.put(Constants.TEMPLATE_NAME, CredentialUtils.getTemplateName(vcRequestDto));
                    templateParams.put(Constants.ISSUER_URI, issuerURI);
                    if (statusListEnabled) {
                        addCredentialStatus(jsonObject);
                    }
                    if (!StringUtils.isEmpty(renderTemplateId)) {
                        templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
                    }
                    jsonObject.put("_holderId", holderId);
                    String unSignedVC = vcFormatter.format(jsonObject, templateParams);
                    Map<String, String> signerSettings = new HashMap<>();
                    // NOTE: This is a quasi implementation to add support for multi-tenancy.
                    signerSettings.put(Constants.APPLICATION_ID, keyChooser.get(vcSignAlgorithm).getFirst());
                    signerSettings.put(Constants.REFERENCE_ID, keyChooser.get(vcSignAlgorithm).getLast());
                    vcResult = vcSigner.attachSignature(unSignedVC, signerSettings);
                } catch(DataProviderExchangeException e) {
                    throw new CertifyException(e.getErrorCode());
                } catch (JSONException e) {
                    log.error(e.getMessage(), e);
                    throw new CertifyException(ErrorConstants.UNKNOWN_ERROR);
                }
                break;
            default:
                throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
        }

        if(vcResult != null && vcResult.getCredential() != null)
            return vcResult;

        log.error("Failed to generate VC : {}", vcResult);
        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.ERROR,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED);
    }

    private CredentialResponse<?> getCredentialResponse(String format, VCResult<?> vcResult) {
        switch (format) {
            case "ldp_vc":
                CredentialResponse<JsonLDObject> ldpVcResponse = new CredentialResponse<>();
                ldpVcResponse.setCredential((JsonLDObject)vcResult.getCredential());
                return ldpVcResponse;
        }
        throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
    }

    private Optional<CredentialMetadata>  getScopeCredentialMapping(String scope, String format) {
        Map<String, Object> vciMetadata = getCredentialIssuerMetadata("latest");
        LinkedHashMap<String, Object> supportedCredentials = (LinkedHashMap<String, Object>) vciMetadata.get("credential_configurations_supported");
        Optional<Map.Entry<String, Object>> result = supportedCredentials.entrySet().stream()
                .filter(cm -> ((LinkedHashMap<String, Object>) cm.getValue()).get("scope").equals(scope)).findFirst();

        if(result.isPresent()) {
            LinkedHashMap<String, Object> metadata = (LinkedHashMap<String, Object>)result.get().getValue();
            CredentialMetadata credentialMetadata = new CredentialMetadata();
            credentialMetadata.setFormat((String) metadata.get("format"));
            credentialMetadata.setScope((String) metadata.get("scope"));
            credentialMetadata.setId(result.get().getKey());
            if(format.equals(VCFormats.LDP_VC)){
                LinkedHashMap<String, Object> credentialDefinition = (LinkedHashMap<String, Object>) metadata.get("credential_definition");
                credentialMetadata.setTypes((List<String>) credentialDefinition.get("type"));
            }
            return Optional.of(credentialMetadata);
        }
        return Optional.empty();
    }

    private void validateLdpVcFormatRequest(CredentialRequest credentialRequest,
                                            CredentialMetadata credentialMetadata) {
        if(!credentialRequest.getCredential_definition().getType().containsAll(credentialMetadata.getTypes()))
            throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_VC_TYPE);

        //TODO need to validate Credential_definition as JsonLD document, if invalid throw exception
    }

    private String getValidClientNonce() {
        VCIssuanceTransaction transaction = vciCacheService.getVCITransaction(parsedAccessToken.getAccessTokenHash());
        //If the transaction is null, it means that VCI service never created cNonce, its authorization server issued cNonce
        String cNonce = (transaction == null) ?
                (String) parsedAccessToken.getClaims().get(Constants.C_NONCE) :
                transaction.getCNonce();
        Object nonceExpireSeconds = parsedAccessToken.getClaims().getOrDefault(Constants.C_NONCE_EXPIRES_IN, 0);
        int cNonceExpire = (transaction == null) ?
                nonceExpireSeconds instanceof Long ? (int)(long)nonceExpireSeconds : (int)nonceExpireSeconds :
                transaction.getCNonceExpireSeconds();
        long issuedEpoch = (transaction == null) ?
                ((Instant) parsedAccessToken.getClaims().getOrDefault(JwtClaimNames.IAT, Instant.MIN)).getEpochSecond():
                transaction.getCNonceIssuedEpoch();

        if( cNonce == null ||
                cNonceExpire <= 0 ||
                (issuedEpoch+cNonceExpire) < LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC) ) {
            log.error("Client Nonce not found / expired in the access token, generate new cNonce");
            transaction = createVCITransaction();
            throw new InvalidNonceException(transaction.getCNonce(), transaction.getCNonceExpireSeconds());
        }
        return cNonce;
    }

    private VCIssuanceTransaction createVCITransaction() {
        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce(securityHelperService.generateSecureRandomString(20));
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));
        transaction.setCNonceExpireSeconds(cNonceExpireSeconds);
        return vciCacheService.setVCITransaction(parsedAccessToken.getAccessTokenHash(), transaction);
    }

    /**
     * Add credential status information to the VC data and store in ledger
     */
    @Transactional
    private void addCredentialStatus(JSONObject jsonObject) {
        try {
            log.info("Adding credential status forstatus list integration");

            // Find or create a suitable status list
            StatusListCredential statusList = statusListCredentialService.findOrCreateStatusList(defaultStatusPurpose);

            // Assign next available index using database approach
            long assignedIndex = statusListCredentialService.findNextAvailableIndex(statusList.getId());

            // If the current list is full, create a new one
            if(assignedIndex == -1) {
                log.info("Current status list is full, creating a new one");
                statusList = statusListCredentialService.generateStatusListCredential(defaultStatusPurpose);
                assignedIndex = statusListCredentialService.findNextAvailableIndex(statusList.getId());

                if(assignedIndex == -1) {
                    log.error("Failed to get available index even from new status list");
                    throw new CertifyException("STATUS_LIST_INDEX_UNAVAILABLE");
                }
            }
            Map<String, Object> indexedAttributes = extractIndexedAttributes(jsonObject);

            // Create credential status object for VC
            JSONObject credentialStatus = new JSONObject();
            String statusId = domainUrl + "/v1/certify/status-list/" + statusList.getId();
            credentialStatus.put("id", statusId + "#" + assignedIndex);
            credentialStatus.put("type", "BitstringStatusListEntry");
            credentialStatus.put("statusPurpose", defaultStatusPurpose);
            credentialStatus.put("statusListIndex", String.valueOf(assignedIndex));
            credentialStatus.put("statusListCredential", statusId);

            // Add credential status to the VC data
            jsonObject.put("credentialStatus", credentialStatus);

            // Extract credential details for ledger storage
            String credentialType = extractCredentialType(jsonObject);

            // Prepare status details for ledger
            Map<String, Object> statusDetails = new HashMap<>();
            statusDetails.put("status_purpose", defaultStatusPurpose);
            statusDetails.put("status_value", false); // Initially not revoked
            statusDetails.put("status_list_credential_id", statusList.getId());
            statusDetails.put("status_list_index", assignedIndex);
            statusDetails.put("cr_dtimes", System.currentTimeMillis());

            // Store in ledger
            storeLedgerEntry(issuerURI, credentialType, statusDetails, indexedAttributes);

            log.info("Successfully added credential status with index {} in status list {} and stored in ledger", assignedIndex, statusList.getId());

        } catch (Exception e) {
            log.error("Error adding credential status", e);
            throw new CertifyException("CREDENTIAL_STATUS_ASSIGNMENT_FAILED");
        }
    }

    private static String extractCredentialType(JSONObject jsonObject) {
        try {
            if(jsonObject.has("type")) {
                Object typeObj = jsonObject.get("type");
                if(typeObj instanceof org.json.JSONArray) {
                    org.json.JSONArray typeArray = (org.json.JSONArray) typeObj;
                    List<String> types = new ArrayList<>();

                    // Extract all types from the array
                    for(int i = 0; i < typeArray.length(); i++) {
                        String type = typeArray.getString(i);
                        if(type != null && !type.trim().isEmpty()) {
                            types.add(type.trim());
                        }
                    }

                    if(!types.isEmpty()) {
                        // Sort the types and join with comma
                        Collections.sort(types);
                        return String.join(",", types);
                    }
                } else {
                    // Single type as string
                    String singleType = typeObj.toString().trim();
                    if(!singleType.isEmpty()) {
                        return singleType;
                    }
                }
            }
            return "VerifiableCredential";
        } catch (Exception e) {
            log.warn("Error extracting credential type, using default", e);
            return "VerifiableCredential";
        }
    }

    // Enhanced version with better complex field support
    public Map<String, Object> extractIndexedAttributes(JSONObject jsonObject) {
        Configuration jsonPathConfig = Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS);
        Map<String, Object> indexedAttributes = new HashMap<>();

        if(jsonObject == null) {
            return indexedAttributes;
        }

        Map<String, String> indexedMappings = indexedAttributesConfig.getIndexedMappings();
        if(indexedMappings.isEmpty()) {
            log.info("No indexed mappings configured, returning empty attributes");
            return indexedAttributes;
        }
        log.info("Indexed Mapping Found: {}", indexedMappings);

        try {
            // Convert credential subject to JSON string forJsonPath processing
            String sourceJsonString = jsonObject.toString();
            for(Map.Entry<String, String> entry : indexedMappings.entrySet()) {
                String targetKey = entry.getKey();
                String pathsConfig = entry.getValue();

                // Support multiple paths separated by pipe (|) forfallback
                String[] paths = pathsConfig.split("\\|");
                Object extractedValue = null;

                for(String jsonPath : paths) {
                    jsonPath = jsonPath.trim();
                    try {
                        // Use JsonPath to read the value from the source JSON
                        extractedValue = JsonPath.using(jsonPathConfig)
                                .parse(sourceJsonString)
                                .read(jsonPath);
                    } catch (Exception e) {
                        log.warn("Error extracting value forpath '{}' and key '{}': {}",
                                jsonPath, targetKey, e.getMessage());
                    }
                }
                // Handle different types of extracted values
                if(extractedValue != null) {
                    Object processedValue = processExtractedIndexedAttributes(extractedValue);
                    indexedAttributes.put(targetKey, processedValue);
                    log.info("Added processed value '{}' to indexed attributes under key '{}'",
                            processedValue, targetKey);
                } else {
                    log.info("No value extracted forkey '{}'; skipping indexing.", targetKey);
                }
            }
        } catch (Exception e) {
            log.error("Error processing credential subject forindexed attributes: {}", e.getMessage(), e);
        }
        return indexedAttributes;
    }

    /**
     * Process extracted values to handle complex types appropriately
     */
    private Object processExtractedIndexedAttributes(Object extractedValue) {
        if(extractedValue == null) {
            return null;
        }

        if(extractedValue instanceof List) {
            List<?> list = (List<?>) extractedValue;
            if(list.isEmpty()) {
                return null;
            }
            if(list.size() == 1) {
                return list.get(0);
            }
            return extractedValue; // Keep as array
        }
        else if(extractedValue instanceof Map) {
            return extractedValue;
        }
        else if(extractedValue instanceof String) {
            String stringValue = (String) extractedValue;
            return stringValue.trim().isEmpty() ? null : stringValue;
        }

        return extractedValue;
    }

    @Transactional
    public void storeLedgerEntry(String issuerId, String credentialType, Map<String, Object> statusDetails, Map<String, Object> indexedAttributes) {
        try {
            Ledger ledger = new Ledger();
            String credentialId = UUID.randomUUID().toString();;
            ledger.setCredentialId(credentialId);
            ledger.setIssuerId(issuerId);
            ledger.setIssueDate(OffsetDateTime.now());
            ledger.setCredentialType(credentialType);
            ledger.setIndexedAttributes(indexedAttributes);

            // Store status details as array
            List<Map<String, Object>> statusDetailsList = new ArrayList<>();
            statusDetailsList.add(statusDetails);
            ledger.setCredentialStatusDetails(statusDetailsList);

            ledgerRepository.save(ledger);
            log.info("Ledger entry stored forcredential: {}", credentialId);
        } catch (Exception e) {
            log.error("Error storing ledger entry", e);
            throw new RuntimeException("Failed to store ledger entry", e);
        }
    }
}
