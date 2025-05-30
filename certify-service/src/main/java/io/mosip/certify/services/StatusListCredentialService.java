package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.StatusListAvailableIndices;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.StatusListAvailableIndicesRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.BitStringUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.certify.vcsigners.VCSigner;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Query;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
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
    private VCSigner vcSigner;

    @Autowired
    private BitStringStatusListService bitStringStatusListService;

    @Autowired
    private StatusListAvailableIndicesRepository statusListAvailableIndicesRepository;

    @Autowired
    private DatabaseStatusListIndexProvider indexProvider;

    @Autowired
    private StatusListIndexProvider statusListIndexProvider;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Value("${mosip.certify.data-provider-plugin.issuer.vc-sign-algo:Ed25519Signature2020}")
    private String vcSignAlgorithm;

    @Value("${mosip.certify.data-provider-plugin.issuer-uri}")
    private String issuerId;

    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    @Value("${mosip.certify.statuslist.default-capacity:131072}")
    private long defaultCapacity;

    @Value("${mosip.certify.statuslist.template-name:StatusList2021Credential}")
    private String statusListTemplateName;

    @Value("${mosip.certify.statuslist.usable-capacity-percentage:50}")
    private long usableCapacityPercentage;

    /**
     * Find a suitable status list for the given purpose
     *
     * @param statusPurpose the purpose of the status list (e.g., "revocation", "suspension")
     * @return Optional containing StatusListCredential if found
     */
    public Optional<StatusListCredential> findSuitableStatusList(String statusPurpose) {
        return statusListCredentialRepository.findSuitableStatusList(statusPurpose);
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
            String statusListId = domainUrl + "/status-list-credentials/" + id;

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
            statusListData.put("issuer", issuerId);
            statusListData.put("validFrom", new Date().toInstant().toString());

            JSONObject credentialSubject = new JSONObject();
            credentialSubject.put("id", statusListId + "#list");
            credentialSubject.put("type", "BitstringStatusList");
            credentialSubject.put("statusPurpose", statusPurpose);

            // Create empty encoded list (all 0s)
            String encodedList = bitStringStatusListService.createEmptyEncodedList(defaultCapacity);
            credentialSubject.put("encodedList", encodedList);

            statusListData.put("credentialSubject", credentialSubject);

            log.debug("Created status list VC structure: {}", statusListData.toString(2));

            // Sign the status list credential
            Map<String, String> signerSettings = new HashMap<>();
            signerSettings.put(Constants.APPLICATION_ID, CertifyIssuanceServiceImpl.keyChooser.get(vcSignAlgorithm).getFirst());
            signerSettings.put(Constants.REFERENCE_ID, CertifyIssuanceServiceImpl.keyChooser.get(vcSignAlgorithm).getLast());

            // Attach signature to the VC
            VCResult<?> vcResult = vcSigner.attachSignature(statusListData.toString(), signerSettings);

            if (vcResult.getCredential() == null) {
                log.error("Failed to generate status list VC - vcResult.getCredential() returned null");
                throw new CertifyException("VC_ISSUANCE_FAILED");
            }
            log.info("VC signed");

            // Convert to byte array for storage
            byte[] vcDocument;
            try {
                vcDocument = vcResult.getCredential().toString().getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                log.error("Error converting VC to byte array", e);
                throw new CertifyException("VC_SERIALIZATION_FAILED");
            }
            log.info("VC document created");
            String vcDocS = vcResult.getCredential().toString();
            log.info(vcDocS);
            // Create and save the status list credential entity
            StatusListCredential statusListCredential = new StatusListCredential();
            statusListCredential.setId(id);
            statusListCredential.setVcDocument(vcDocS);
            statusListCredential.setCredentialType("BitstringStatusListCredential");
            statusListCredential.setStatusPurpose(statusPurpose);
            statusListCredential.setCapacity(defaultCapacity);
            statusListCredential.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
            statusListCredential.setCreatedDtimes(LocalDateTime.now());

            // Save to database
            StatusListCredential savedCredential = statusListCredentialRepository.save(statusListCredential);
            log.info("Saved StatusListCredential: ID={}, CreatedDtimes={}",
                    savedCredential.getId(), savedCredential.getCreatedDtimes());
            statusListCredentialRepository.flush();
            log.info("Transaction explicitly flushed and committed for StatusListCredential ID: {}", savedCredential.getId());

            // Initialize available indices for the new status list
            initializeAvailableIndices(savedCredential);

//            return savedCredential;
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
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    private void initializeAvailableIndices(StatusListCredential statusListCredential) {
        log.info("Initializing available indices for status list: {}", statusListCredential.getId());

        try {

            EntityManager entityManager = entityManagerFactory.createEntityManager();
            Query checkQuery = entityManager.createNativeQuery(
                    "SELECT COUNT(*) FROM status_list_credential WHERE id = ?");
            checkQuery.setParameter(1, statusListCredential.getId());
            Object count = checkQuery.getSingleResult();
            log.info("StatusListCredential with ID {} exists in DB: {}",
                    statusListCredential.getId(), count);
            // Use native SQL for bulk insert
            String insertSql = """
            INSERT INTO status_list_available_indices
            (status_list_credential_id, list_index, is_assigned, cr_dtimes)
            SELECT ?, generate_series(0, ? - 1), false, NOW()
            """;

            // Get the entity manager for native query execution

            try {
                entityManager.getTransaction().begin();

                Query nativeQuery = entityManager.createNativeQuery(insertSql);
                nativeQuery.setParameter(1, statusListCredential.getId());
                nativeQuery.setParameter(2, statusListCredential.getCapacity());

                int rowsInserted = nativeQuery.executeUpdate();

                entityManager.getTransaction().commit();

                log.info("Successfully initialized {} available indices for status list: {}",
                        rowsInserted, statusListCredential.getId());

            } catch (Exception e) {
                if (entityManager.getTransaction().isActive()) {
                    entityManager.getTransaction().rollback();
                }
                throw e;
            } finally {
                entityManager.close();
            }

        } catch (Exception e) {
            log.error("Error initializing available indices for status list: {}",
                    statusListCredential.getId(), e);
            throw new CertifyException("STATUS_LIST_INDEX_INITIALIZATION_FAILED");
        }
    }

//    /**
//     * Initialize available indices for a newly created status list
//     * Populates the status_list_available_indices table with all indices set to unassigned
//     *
//     * @param statusListCredential the status list credential
//     */
//    @Transactional
//    private void initializeAvailableIndices(StatusListCredential statusListCredential) {
//        log.info("Initializing available indices for status list: {}", statusListCredential.getId());
//
//        try {
//            List<StatusListAvailableIndices> availableIndices = new ArrayList<>();
//
//            // Create entries for all indices from 0 to capacity-1
//            for (long i = 0; i < statusListCredential.getCapacity(); i++) {
//                StatusListAvailableIndices indexEntry = new StatusListAvailableIndices();
//                indexEntry.setStatusListCredentialId(statusListCredential.getId());
//                indexEntry.setListIndex(i);
//                indexEntry.setIsAssigned(false);
//                indexEntry.setCreatedDtimes(LocalDateTime.now());
//
//                availableIndices.add(indexEntry);
//            }
//
//            // Batch save all indices
//            statusListAvailableIndicesRepository.saveAll(availableIndices);
//
//            log.info("Successfully initialized {} available indices for status list: {}",
//                    statusListCredential.getCapacity(), statusListCredential.getId());
//
//        } catch (Exception e) {
//            log.error("Error initializing available indices for status list: {}",
//                    statusListCredential.getId(), e);
//            throw new CertifyException("STATUS_LIST_INDEX_INITIALIZATION_FAILED");
//        }
//    }

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
        Optional<StatusListCredential> existingStatusList = findSuitableStatusList(statusPurpose);

        if (existingStatusList.isPresent()) {
            return existingStatusList.get();
        }

        // No suitable status list found, generate a new one
        log.info("No suitable status list found, generating a new one");
        StatusListCredential statusListCredential = generateStatusListCredential(statusPurpose);
        return statusListCredential;
    }

    /**
     * Find next available index in the status list using the configured index provider
     *
     * @param statusListId the ID of the status list
     * @return the next available index, or -1 if the list is full
     */
    public long findNextAvailableIndex(String statusListId) {
        Optional<Long> availableIndex = statusListIndexProvider.acquireIndex(statusListId, Map.of());
        return availableIndex.orElse(-1L);
    }

//    /**
//     * Find next available index using Database Query Approach with Skip Lock
//     *
//     * @param statusListId the ID of the status list
//     * @return the next available index, or -1 if the list is full
//     */
//    @Transactional
//    public long findNextAvailableIndex(String statusListId) {
//        log.info("Finding next available index for status list: {}", statusListId);
//
//        Optional<StatusListCredential> statusListOpt = statusListCredentialRepository.findById(statusListId);
//
//        if (statusListOpt.isEmpty()) {
//            log.error("Status list not found with ID: {}", statusListId);
//            throw new CertifyException("STATUS_LIST_NOT_FOUND");
//        }
//
//        StatusListCredential statusList = statusListOpt.get();
//
//        // Check if list is already marked as full
//        if (statusList.getCredentialStatus() == StatusListCredential.CredentialStatus.FULL) {
//            log.info("Status list is already marked as full: {}", statusListId);
//            return -1;
//        }
//
//        // Get usable capacity from configuration (defaulting to 50% if not configured)
//        long effectiveThresholdCount = (long) Math.floor(statusList.getCapacity() * (usableCapacityPercentage / 100.0));
//
//        // Preliminary usable capacity check
//        long currentAssignedCount = statusListAvailableIndicesRepository.countByStatusListCredentialIdAndIsAssigned(statusListId, true);
//
//        if (currentAssignedCount >= effectiveThresholdCount) {
//            log.info("Status list {} has reached usable capacity limit ({}/{})",
//                    statusListId, currentAssignedCount, effectiveThresholdCount);
//
//            // Mark the status list as full
//            statusList.setCredentialStatus(StatusListCredential.CredentialStatus.FULL);
//            statusListCredentialRepository.save(statusList);
//
//            return -1;
//        }
//
//        // Attempt to atomically claim an index using skip lock
//        Optional<Long> claimedIndex = statusListAvailableIndicesRepository.claimNextAvailableIndex(statusListId);
//
//        if (claimedIndex.isPresent()) {
//            log.info("Successfully claimed index {} for status list {}", claimedIndex.get(), statusListId);
//
//            // Check if we've reached the threshold after this assignment
//            long newAssignedCount = currentAssignedCount + 1;
//            if (newAssignedCount >= effectiveThresholdCount) {
//                statusList.setCredentialStatus(StatusListCredential.CredentialStatus.FULL);
//                statusListCredentialRepository.save(statusList);
//                log.info("Status list {} marked as full after reaching threshold", statusListId);
//            }
//
//            return claimedIndex.get();
//        } else {
//            log.warn("No available index could be claimed for status list {}", statusListId);
//            return -1;
//        }
//    }

//    /**
//     * Find next available index in the status list
//     *
//     * @param statusListId the ID of the status list
//     * @return the next available index, or -1 if the list is full
//     */
//    public long findNextAvailableIndex(String statusListId) {
//        Optional<StatusListCredential> statusListOpt = statusListCredentialRepository.findById(statusListId);
//
//        if (statusListOpt.isEmpty()) {
//            log.error("Status list not found with ID: {}", statusListId);
//            throw new CertifyException("STATUS_LIST_NOT_FOUND");
//        }
//
//        StatusListCredential statusList = statusListOpt.get();
//        if (statusList.getCredentialStatus() == StatusListCredential.CredentialStatus.FULL) {
//            log.info("Status list is full: {}", statusListId);
//            return -1;
//        }
//
//        // Get the status list data and find next available index
//        JsonLDObject statusListVC = deserializeVC(statusList.getVcDocument());
//        String encodedList = getEncodedListFromVC(statusListVC);
//
//        long nextIndex = bitStringStatusListService.findNextAvailableIndex(encodedList);
//
//        // Check if the list is now full after this allocation
//        if (nextIndex == -1 || nextIndex >= statusList.getCapacity() - 1) {
//            statusList.setCredentialStatus(StatusListCredential.CredentialStatus.FULL);
//            statusListCredentialRepository.save(statusList);
//
//            if (nextIndex == -1) {
//                return -1; // No available index found
//            }
//        }
//
//        return nextIndex;
//    }

    /**
     * Get the status list credential by ID
     *
     * @param statusListId the ID of the status list
     * @return StatusListCredential
     */
    public StatusListCredential getStatusListCredential(String statusListId) {
        return statusListCredentialRepository.findById(statusListId)
                .orElseThrow(() -> new CertifyException("STATUS_LIST_NOT_FOUND"));
    }

    // Helper methods

    /**
     * Deserialize VC document from byte array
     *
     * @param vcDocument byte array of VC document
     * @return JsonLDObject representation of the VC
     */
    private JsonLDObject deserializeVC(byte[] vcDocument) {
        try {
            String vcString = new String(vcDocument);
            return JsonLDObject.fromJson(vcString);
        } catch (Exception e) {
            log.error("Error deserializing VC document", e);
            throw new CertifyException("INVALID_VC_DOCUMENT");
        }
    }

    /**
     * Extract encodedList from VC
     *
     * @param statusListVC the status list VC
     * @return encodedList string
     */
    private String getEncodedListFromVC(JsonLDObject statusListVC) {
        try {
            Map<String, Object> credentialSubject = (Map<String, Object>) statusListVC.getJsonObject().get("credentialSubject");
            Map<String, Object> statusList = (Map<String, Object>) credentialSubject.get("statusList");
            return (String) statusList.get("encodedList");
        } catch (Exception e) {
            log.error("Error extracting encodedList from VC", e);
            throw new CertifyException("INVALID_VC_DOCUMENT");
        }
    }

    /**
     * Assign the next available index from a status list and mark it as used
     * Uses Database Query Approach with FOR UPDATE SKIP LOCKED for concurrent safety
     *
     * @param statusListId the ID of the status list credential
     * @return the assigned index, or -1 if no index is available
     */
    @Transactional
    public long assignIndexAndMarkUsed(String statusListId) {
        log.debug("Attempting to assign index for status list: {}", statusListId);

        EntityManager entityManager = entityManagerFactory.createEntityManager();

        try {
            entityManager.getTransaction().begin();

            // Database approach for index assignment with atomic operation
            String sql = """
            WITH available_slot AS (
                SELECT list_index
                FROM status_list_available_indices
                WHERE status_list_credential_id = ?
                AND is_assigned = FALSE
                ORDER BY RANDOM()
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE status_list_available_indices sla
            SET is_assigned = TRUE, upd_dtimes = NOW()
            FROM available_slot avs
            WHERE sla.status_list_credential_id = ?
            AND sla.list_index = avs.list_index
            AND sla.is_assigned = FALSE
            RETURNING sla.list_index
            """;

            Query nativeQuery = entityManager.createNativeQuery(sql);
            nativeQuery.setParameter(1, statusListId);
            nativeQuery.setParameter(2, statusListId);

            List<?> results = nativeQuery.getResultList();

            entityManager.getTransaction().commit();

            if (!results.isEmpty()) {
                Object result = results.get(0);
                long assignedIndex;

                // Handle different return types (BigInteger, Integer, Long)
                if (result instanceof BigInteger) {
                    assignedIndex = ((BigInteger) result).longValue();
                } else if (result instanceof Integer) {
                    assignedIndex = ((Integer) result).longValue();
                } else if (result instanceof Long) {
                    assignedIndex = (Long) result;
                } else {
                    assignedIndex = Long.parseLong(result.toString());
                }

                log.debug("Successfully assigned index {} for status list: {}", assignedIndex, statusListId);
                return assignedIndex;
            } else {
                log.warn("No available index found for status list: {}", statusListId);
                return -1;
            }

        } catch (Exception e) {
            if (entityManager.getTransaction().isActive()) {
                entityManager.getTransaction().rollback();
            }
            log.error("Error assigning index for status list: {}", statusListId, e);
            throw new CertifyException("STATUS_LIST_INDEX_ASSIGNMENT_FAILED");
        } finally {
            entityManager.close();
        }
    }
}