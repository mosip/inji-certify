package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.config.IndexedAttributesConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.repository.StatusListAvailableIndicesRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.BitStringStatusListUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.*;

/**
 * Service class for managing Status List Credentials
 * Responsible for generating, retrieving, and managing status list VCs
 */
@Slf4j
@Service
public class StatusListCredentialService {

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    private VCFormatter vcFormatter;

    @Autowired
    private CredentialFactory credentialFactory;

    @Autowired
    private DatabaseStatusListIndexProvider indexProvider;

    @Autowired
    private LedgerRepository ledgerRepository;

    @Autowired
    private IndexedAttributesConfig indexedAttributesConfig;

    @PersistenceContext
    private EntityManager entityManager;

    @Value("${mosip.certify.status-list.signature-crypto-suite:Ed25519Signature2020}")
    private String signatureCryptoSuite;

    @Value("${mosip.certify.status-list.signature-algo:EdDSA}")
    private String signatureAlgo;

    @Value("${mosip.certify.data-provider-plugin.did-url}")
    private String didUrl;

    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    @Value("#{${mosip.certify.statuslist.size-in-kb:16}}") // value in kb
    private long statusListSizeInKB;

    @Value("#{${mosip.certify.signature-cryptosuite.key-alias-mapper}}")
    private Map<String, List<List<String>>> keyAliasMapper;

    @Value("${mosip.certify.status-list.key-manager-ref-id:ED25519_SIGN}")
    private String statusListKeyManagerRefId;

    public String getStatusListCredential(String id) throws CertifyException {
        log.info("Processing status list credential request for ID: {}", id);

        StatusListCredential statusList = findStatusListById(id)
                .orElseThrow(() -> new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND));

        try {
            JSONObject vcDocument = new JSONObject(statusList.getVcDocument());
            log.info("Successfully retrieved status list credential for ID: {}", id);

            // Convert JSONObject to Map for consistent return type
            return vcDocument.toString();

        } catch (Exception e) {
            log.error("Unexpected error retrieving status list credential with ID: {}", id, e);
            throw new CertifyException(ErrorConstants.STATUS_RETRIEVAL_ERROR);
        }
    }

    /**
     * Find status list credential by ID
     *
     * @param id the ID of the status list credential
     * @return Optional containing StatusListCredential if found
     */
    public Optional<StatusListCredential> findStatusListById(String id) {
        log.info("Finding status list credential by ID: {}", id);

        try {
            return statusListCredentialRepository.findById(id);
        } catch (Exception e) {
            log.error("Error finding status list credential by ID: {}", id, e);
            return Optional.empty();
        }
    }

    /**
     * Find a suitable status list for the given purpose
     *
     * @param statusPurpose the purpose of the status list (e.g., "revocation", "suspension")
     * @return Optional containing StatusListCredential if found
     */
    public Optional<StatusListCredential> findSuitableStatusList(String statusPurpose, StatusListCredential.CredentialStatus status) {
        return statusListCredentialRepository.findSuitableStatusList(statusPurpose, status);
    }

    /**
     * Generate a new status list credential for the specified purpose
     *
     * @param statusPurpose the purpose of the status list (e.g., "revocation", "suspension")
     * @return the generated StatusListCredential
     */
    @Transactional
    public StatusListCredential generateStatusListCredential(String statusPurpose) {
        log.info("Generating new status list credential with purpose: {}", statusPurpose);

        try {
            // Generate unique ID for status list
            String id = UUID.randomUUID().toString();
            String statusListId = domainUrl + "/v1/certify/credentials/status-list/" + id;

            // Create the template data for the status list VC
            JSONObject statusListData = new JSONObject();

            JSONArray contextList = new JSONArray();
            contextList.put("https://www.w3.org/ns/credentials/v2");
            statusListData.put("@context", contextList);

            JSONArray typeList = new JSONArray();
            typeList.put("VerifiableCredential");
            typeList.put("BitstringStatusListCredential");
            statusListData.put("type", typeList);

            statusListData.put("id", statusListId);
            statusListData.put("issuer", didUrl);
            statusListData.put("validFrom", new Date().toInstant().toString());

            JSONObject credentialSubject = new JSONObject();
            credentialSubject.put("id", statusListId);
            credentialSubject.put("type", "BitstringStatusList");
            credentialSubject.put("statusPurpose", statusPurpose);

            // Create empty encoded list (all 0s)
            String encodedList = BitStringStatusListUtils.createEmptyEncodedList(statusListSizeInKB);
            credentialSubject.put("encodedList", encodedList);

            statusListData.put("credentialSubject", credentialSubject);

            log.debug("Created status list VC structure: {}", statusListData.toString(2));

            String vcDocS = addProofAndHandleResult(statusListData, ErrorConstants.VC_ISSUANCE_FAILED);

            // Create and save the status list credential entity
            StatusListCredential statusListCredential = new StatusListCredential();
            statusListCredential.setId(id);
            statusListCredential.setVcDocument(vcDocS);
            statusListCredential.setCredentialType("BitstringStatusListCredential");
            statusListCredential.setStatusPurpose(statusPurpose);
            statusListCredential.setCapacity(statusListSizeInKB);
            statusListCredential.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
            statusListCredential.setCreatedDtimes(LocalDateTime.now());

            // Save to database
            StatusListCredential savedCredential = statusListCredentialRepository.saveAndFlush(statusListCredential);
            log.info("Saved StatusListCredential: ID={}, CreatedDtimes={}", savedCredential.getId(), savedCredential.getCreatedDtimes());
            initializeAvailableIndices(savedCredential);

            return savedCredential;

        } catch (JSONException e) {
            log.error("JSON error while generating status list credential", e);
            throw new CertifyException("STATUS_LIST_JSON_ERROR");
        } catch (Exception e) {
            log.error("Error generating status list credential", e);
            throw new CertifyException("STATUS_LIST_GENERATION_FAILED");
        }
    }

    /**
     * Initialize available indices for a newly created status list using Database Query Approach
     *
     * @param statusListCredential the status list credential
     */
    @Transactional
    public void initializeAvailableIndices(StatusListCredential statusListCredential) {
        log.info("Initializing available indices for status list: {}", statusListCredential.getId());

        try {

            Query checkQuery = entityManager.createNativeQuery("SELECT COUNT(*) FROM status_list_credential WHERE id = ?");
            checkQuery.setParameter(1, statusListCredential.getId());
            Object count = checkQuery.getSingleResult();
            log.info("StatusListCredential with ID {} exists in DB: {}", statusListCredential.getId(), count);

            String insertSql = """
                    INSERT INTO status_list_available_indices
                    (status_list_credential_id, list_index, is_assigned, cr_dtimes)
                    SELECT ?, generate_series(0, ? - 1), false, NOW()
                    """;

            Query nativeQuery = entityManager.createNativeQuery(insertSql);
            nativeQuery.setParameter(1, statusListCredential.getId());
            nativeQuery.setParameter(2, statusListCredential.getCapacity());

            int rowsInserted = nativeQuery.executeUpdate();
            log.info("Successfully initialized {} available indices for status list: {}", rowsInserted, statusListCredential.getId());
        } catch (Exception e) {
            log.error("Error initializing available indices for status list: {}", statusListCredential.getId(), e);
            throw new CertifyException("STATUS_LIST_INDEX_INITIALIZATION_FAILED");
        }
    }

    /**
     * Find or create a suitable status list for the given purpose
     * If no suitable status list exists, a new one will be created
     *
     * @param statusPurpose the purpose of the status list
     * @return StatusListCredential that can be used for the given purpose
     */
    @Transactional
    public StatusListCredential findOrCreateStatusList(String statusPurpose) {
        log.info("Finding or creating status list for purpose: {}", statusPurpose);

        // Try to find an existing suitable status list
        return findSuitableStatusList(statusPurpose, StatusListCredential.CredentialStatus.AVAILABLE)
                .orElseGet(() -> {
                    log.info("No suitable status list found, generating a new one");
                    return generateStatusListCredential(statusPurpose);
                });
    }

    /**
     * Find next available index in the status list using the configured index provider
     *
     * @param statusListId the ID of the status list
     * @return the next available index, or -1 if the list is full
     */
    public long findNextAvailableIndex(String statusListId) {
        Optional<Long> availableIndex = indexProvider.acquireIndex(statusListId, Map.of());
        return availableIndex.orElse(-1L);
    }

    // Add this method to StatusListCredentialService.java

    /**
     * Re-sign a status list credential with updated content
     *
     * @param vcDocumentJson The updated VC document as JSON string
     * @return The re-signed VC document as JSON string
     */
    @Transactional
    public String resignStatusListCredential(String vcDocumentJson) {
        log.info("Re-signing status list credential");

        try {
            // Remove existing proof if present before re-signing
            JSONObject vcDocument = new JSONObject(vcDocumentJson);
            if (vcDocument.has("proof")) {
                vcDocument.remove("proof");
            }

            // Update validFrom timestamp to current time
            vcDocument.put("validFrom", new Date().toInstant().toString());
            return addProofAndHandleResult(vcDocument, ErrorConstants.VC_RESIGNATION_FAILED);
        } catch (Exception e) {
            log.error("Error re-signing status list credential", e);
            throw new CertifyException(ErrorConstants.VC_RESIGNATION_FAILED);
        }
    }

    @Transactional
    public void addCredentialStatus(JSONObject jsonObject, String statusPurpose) throws CertifyException {
        log.info("Adding credential status for status list integration");

        // Assign next available index using database approach
        StatusListCredential statusList = findOrCreateStatusList(statusPurpose);
        long assignedIndex = findNextAvailableIndex(statusList.getId());

        if (assignedIndex == -1) {
            log.info("Current status list is full, creating a new one");
            statusList = generateStatusListCredential(statusPurpose);
            assignedIndex = findNextAvailableIndex(statusList.getId());

            if (assignedIndex == -1) {
                log.error("Failed to get available index even from new status list");
                throw new CertifyException("STATUS_LIST_INDEX_UNAVAILABLE");
            }
        }

        Map<String, Object> indexedAttributes = extractIndexedAttributes(jsonObject);

        JSONObject credentialStatus = new JSONObject();
            String statusId = domainUrl + "/v1/certify/credentials/status-list/" + statusList.getId();
        credentialStatus.put("id", statusId + "#" + assignedIndex);
        credentialStatus.put("type", "BitstringStatusListEntry");
        credentialStatus.put("statusPurpose", statusPurpose);
        credentialStatus.put("statusListIndex", String.valueOf(assignedIndex));
        credentialStatus.put("statusListCredential", statusId);
        jsonObject.put(VCDM2Constants.CREDENTIAL_STATUS, credentialStatus);

        String credentialType = extractCredentialType(jsonObject);

        Map<String, Object> statusDetails = new HashMap<>();
        statusDetails.put("status_purpose", statusPurpose);
        statusDetails.put("status_value", false); // Initially not revoked
        statusDetails.put("status_list_credential_id", statusList.getId());
        statusDetails.put("status_list_index", assignedIndex);
        statusDetails.put("cr_dtimes", System.currentTimeMillis());

        String credentialId = null;
        if(jsonObject.has("credentialId")) {
            credentialId = jsonObject.getString("credentialId");
        }
        storeLedgerEntry(credentialId, didUrl, credentialType, statusDetails, indexedAttributes);

        log.info("Successfully added credential status with index {} in status list {} and stored in ledger", assignedIndex, statusList.getId());
    }

    private static String extractCredentialType(JSONObject jsonObject) {
        try {
            if(jsonObject.has(Constants.TYPE)) {
                Object typeObj = jsonObject.get(Constants.TYPE);
                if (typeObj instanceof org.json.JSONArray typeArray) {
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

        String sourceJsonString = jsonObject.toString();
        for (Map.Entry<String, String> entry : indexedMappings.entrySet()) {
            String targetKey = entry.getKey();
            String pathsConfig = entry.getValue();
            String[] paths = pathsConfig.split("\\|");
            Object extractedValue = null;

            for (String jsonPath : paths) {
                jsonPath = jsonPath.trim();
                try {
                    extractedValue = JsonPath.using(jsonPathConfig).parse(sourceJsonString).read(jsonPath);
                    if (extractedValue != null) {
                        break; // Found a value, no need to check other fallback paths
                    }
                } catch (Exception e) {
                    log.warn("Error extracting value for path '{}' and key '{}': {}", jsonPath, targetKey, e.getMessage());
                }
            }

            if (extractedValue != null) {
                Object processedValue = processExtractedIndexedAttributes(extractedValue);
                if (processedValue != null) {
                    indexedAttributes.put(targetKey, processedValue);
                    log.info("Added processed value '{}' to indexed attributes under key '{}'", processedValue, targetKey);
                }
            } else {
                log.info("No value extracted for key '{}'; skipping indexing.", targetKey);
            }
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
        if (extractedValue instanceof List<?> list) {
            if (list.isEmpty()) {
                return null;
            }
            return list.size() == 1 ? list.get(0) : extractedValue;
        } else if (extractedValue instanceof String stringValue) {
            return stringValue.trim().isEmpty() ? null : stringValue;
        }

        return extractedValue;
    }

    @jakarta.transaction.Transactional
    public void storeLedgerEntry(String credentialId, String issuerId, String credentialType, Map<String, Object> statusDetails, Map<String, Object> indexedAttributes) {
        try {
            Ledger ledger = new Ledger();
            if(credentialId != null) {
                ledger.setCredentialId(credentialId);
            }
            ledger.setIssuerId(issuerId);
            ledger.setIssueDate(OffsetDateTime.now());
            ledger.setCredentialType(credentialType);
            ledger.setIndexedAttributes(indexedAttributes);

            // Store status details as array
            List<Map<String, Object>> statusDetailsList = new ArrayList<>();
            statusDetailsList.add(statusDetails);
            ledger.setCredentialStatusDetails(statusDetailsList);

            ledgerRepository.save(ledger);
        } catch (Exception e) {
            log.error("Error storing ledger entry", e);
            throw new RuntimeException("Failed to store ledger entry", e);
        }
    }

    /**
     * Helper method to add a proof to a VC and handle the result.
     */
    private String addProofAndHandleResult(JSONObject vcDocument, String errorConstant) throws CertifyException {
        String appId = keyAliasMapper.get(signatureCryptoSuite).getFirst().getFirst();
        Credential cred = credentialFactory.getCredential(VCFormats.LDP_VC)
                .orElseThrow(() -> new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT));

        VCResult<?> vcResult = cred.addProof(
                vcDocument.toString(),
                "",
                signatureAlgo,
                appId,
                statusListKeyManagerRefId,
                didUrl,
                signatureCryptoSuite
        );

        if (vcResult.getCredential() == null) {
            log.error("Failed to add proof to VC - vcResult.getCredential() returned null");
            throw new CertifyException(errorConstant);
        }
        return vcResult.getCredential().toString();
    }

}