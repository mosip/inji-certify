/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import java.text.ParseException;
import java.time.OffsetDateTime;
import java.util.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.certify.api.util.AuditHelper;
import io.mosip.certify.config.IndexedAttributesConfig;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.VCIssuanceUtil;
import jakarta.transaction.Transactional;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.validators.CredentialRequestValidator;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.enums.CredentialFormat;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.CredentialUtils;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONException;

import static io.mosip.certify.utils.VCIssuanceUtil.*;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "DataProvider")
public class CertifyIssuanceServiceImpl implements VCIssuanceService {

    public static final Map<String, List<String>> keyChooser = Map.of(
            SignatureAlg.RSA_SIGNATURE_SUITE_2018, List.of(Constants.CERTIFY_VC_SIGN_RSA, Constants.EMPTY_REF_ID),
            SignatureAlg.ED25519_SIGNATURE_SUITE_2018, List.of(Constants.CERTIFY_VC_SIGN_ED25519, Constants.ED25519_REF_ID),
            SignatureAlg.ED25519_SIGNATURE_SUITE_2020, List.of(Constants.CERTIFY_VC_SIGN_ED25519, Constants.ED25519_REF_ID),
            SignatureAlg.EC_K1_2016, List.of(Constants.CERTIFY_VC_SIGN_EC_K1, Constants.EC_SECP256K1_SIGN),
            SignatureAlg.EC_SECP256K1_2019, List.of(Constants.CERTIFY_VC_SIGN_EC_K1, Constants.EC_SECP256K1_SIGN),
            SignatureAlg.EC_SECP256R1_2019, List.of(Constants.CERTIFY_VC_SIGN_EC_R1, Constants.EC_SECP256R1_SIGN));
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
    private CredentialFactory credentialFactory;

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

    private Map<String, Object> didDocument;

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Value("${mosip.certify.identifier}")
    private String certifyIssuer;

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
            Optional<CredentialMetadata> result = getScopeCredentialMapping(scope, credentialRequest.getFormat(), credentialConfigurationService.fetchCredentialIssuerMetadata("latest"), credentialRequest);
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
        String cNonce = VCIssuanceUtil.getValidClientNonce(vciCacheService, parsedAccessToken, cNonceExpireSeconds, securityHelperService, log);
        // c_nonce present in accessToken but not in proofjwt
        if (parsedAccessToken.getClaims().containsKey(Constants.C_NONCE)
                && credentialRequest.getProof().getJwt() != null) {
            // issue a c_nonce and return the error
            try {
                SignedJWT proofJwt = SignedJWT.parse(credentialRequest.getProof().getJwt());
                String proofJwtNonce = Optional.ofNullable(proofJwt.getJWTClaimsSet().getStringClaim("nonce")).orElse("");
                String authZServerNonce = Optional.ofNullable(parsedAccessToken.getClaims().get(Constants.C_NONCE)).map(Object::toString).orElse("");
                if (authZServerNonce.equals(StringUtils.EMPTY) || !cNonce.equals(proofJwtNonce)) {
                    // AuthZ server didn't give in a protected c_nonce
                    //  and c_nonce given in proofJwt doesn't match Certify generated c_nonce
                    throw new InvalidNonceException(cNonce, cNonceExpireSeconds);
                }
            } catch (ParseException e) {
                // check iff specific error exists for invalid holderKey
                throw new CertifyException(ErrorConstants.INVALID_PROOF, "error parsing proof jwt");
            }
        } else {
            throw new InvalidNonceException(cNonce, cNonceExpireSeconds);
        }
        ProofValidator proofValidator = proofValidatorFactory.getProofValidator(credentialRequest.getProof().getProof_type());
        String validCNonce = VCIssuanceUtil.getValidClientNonce(vciCacheService, parsedAccessToken, cNonceExpireSeconds, securityHelperService, log);
        if(!proofValidator.validateV2((String)parsedAccessToken.getClaims().get(Constants.CLIENT_ID), validCNonce,
                credentialRequest.getProof(), credentialMetadata.getProofTypesSupported())) {
            throw new CertifyException(ErrorConstants.INVALID_PROOF);
        }

        // 4. Get VC from configured plugin implementation
        VCResult<?> vcResult = getVerifiableCredential(credentialRequest, credentialMetadata,
                proofValidator.getKeyMaterial(credentialRequest.getProof()));

        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        return VCIssuanceUtil.getCredentialResponse(credentialRequest.getFormat(), vcResult);
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

    private VCResult<?> getVerifiableCredential(CredentialRequest credentialRequest, CredentialMetadata credentialMetadata,String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialRequest.getFormat());

        switch (credentialRequest.getFormat()) {
            case "ldp_vc" :
                VCResult<JsonLDObject> VC = new VCResult<>();
                vcRequestDto.setContext(credentialRequest.getCredential_definition().getContext());
                vcRequestDto.setType(credentialRequest.getCredential_definition().getType());
                vcRequestDto.setCredentialSubject(credentialRequest.getCredential_definition().getCredentialSubject());
                validateLdpVcFormatRequest(credentialRequest, credentialMetadata);
                try {
                    // TODO(multitenancy): later decide which plugin out of n plugins is the correct one
                    JSONObject jsonObject = dataProviderPlugin.fetchData(parsedAccessToken.getClaims());
                    Map<String, Object> templateParams = new HashMap<>();
                    String templateName = CredentialUtils.getTemplateName(vcRequestDto);
                    templateParams.put(Constants.TEMPLATE_NAME, templateName);
                    templateParams.put(Constants.ISSUER_URI, issuerURI);
                    if (statusListEnabled) {
                        addCredentialStatus(jsonObject);
                    }
                    if (!StringUtils.isEmpty(renderTemplateId)) {
                        templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
                    }
                    jsonObject.put("_holderId", holderId);
                    Credential cred = credentialFactory.getCredential(credentialRequest.getFormat()).orElseThrow(()-> new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT));
                    templateParams.putAll(jsonObject.toMap());
                    String unsignedCredential=cred.createCredential(templateParams, templateName);
                    return cred.addProof(unsignedCredential,"", vcFormatter.getProofAlgorithm(templateName), vcFormatter.getAppID(templateName), vcFormatter.getRefID(templateName),vcFormatter.getDidUrl(templateName));
                } catch(DataProviderExchangeException e) {
                    throw new CertifyException(e.getErrorCode());
                } catch (JSONException e) {
                    log.error(e.getMessage(), e);
                    throw new CertifyException(ErrorConstants.UNKNOWN_ERROR);
                }
                case "vc+sd-jwt":
                vcRequestDto.setSdJwtVct(credentialRequest.getSdJwtVct());
                try {
                    // TODO(multitenancy): later decide which plugin out of n plugins is the correct one
                    JSONObject jsonObject = dataProviderPlugin.fetchData(parsedAccessToken.getClaims());
                    Map<String, Object> templateParams = new HashMap<>();
                    String templateName = CredentialUtils.getTemplateName(vcRequestDto);
                    templateParams.put(Constants.TEMPLATE_NAME, templateName);
                    templateParams.put(Constants.ISSUER_URI, issuerURI);
                    if (!StringUtils.isEmpty(renderTemplateId)) {
                        templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
                    }
                    Credential cred = credentialFactory.getCredential(CredentialFormat.VC_SD_JWT.toString()).orElseThrow(()-> new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT));
                    jsonObject.put("_holderId", holderId);
                    templateParams.putAll(jsonObject.toMap());
                    templateParams.put("_vct", vcRequestDto.getSdJwtVct());
                    // This is with reference to the Representation of a Key ID for a Proof-of-Possession Key
                    // Ref: https://datatracker.ietf.org/doc/html/rfc7800#section-3.4
                    templateParams.put("_cnf", Map.of("kid", holderId));
                    templateParams.put("_iss", certifyIssuer);
                    String unsignedCredential=cred.createCredential(templateParams, templateName);
                    return cred.addProof(unsignedCredential,"", vcFormatter.getProofAlgorithm(templateName), vcFormatter.getAppID(templateName), vcFormatter.getRefID(templateName),vcFormatter.getDidUrl(templateName));
                } catch(DataProviderExchangeException e) {
                    log.error("Error processing the SD-JWT :", e);
                    throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED);
                }
                default:
                    throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
            }
    }

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
            String credentialId = UUID.randomUUID().toString();
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
