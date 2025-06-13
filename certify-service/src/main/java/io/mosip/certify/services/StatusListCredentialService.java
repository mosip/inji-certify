package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.StatusListAvailableIndicesRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.BitStringStatusListUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.certify.vcsigners.VCSigner;
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
    private DatabaseStatusListIndexProvider indexProvider;

    @PersistenceContext
    private EntityManager entityManager;

    @Value("${mosip.certify.data-provider-plugin.issuer.vc-sign-algo:Ed25519Signature2020}")
    private String vcSignAlgorithm;

    @Value("${mosip.certify.data-provider-plugin.issuer-uri}")
    private String issuerId;

    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    @Value("#{${mosip.certify.statuslist.default-capacity:16} * 1024 * 8}") // value in kb
    private long defaultCapacity;

    public String getStatusListCredential(String id) throws CertifyException {
        log.info("Processing status list credential request for ID: {}", id);

        try {
            // Find the status list credential by ID
            Optional<StatusListCredential> statusListOpt = findStatusListById(id);

            if (statusListOpt.isEmpty()) {
                log.warn("Status list credential not found for ID: {}", id);
                throw new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND);
            }

            StatusListCredential statusList = statusListOpt.get();

            // Parse the VC document
            JSONObject vcDocument;
            try {
                vcDocument = new JSONObject(statusList.getVcDocument());
            } catch (Exception e) {
                log.error("Error parsing VC document for status list ID: {}", id, e);
                throw new CertifyException(ErrorConstants.STATUS_RETRIEVAL_ERROR);
            }

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
            String statusListId = domainUrl + "/status-list/" + id;

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
            credentialSubject.put("id", statusListId);
            credentialSubject.put("type", "BitstringStatusList");
            credentialSubject.put("statusPurpose", statusPurpose);

            // Create empty encoded list (all 0s)
            String encodedList = BitStringStatusListUtils.createEmptyEncodedList(defaultCapacity);
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

            // Convert to byte array for storage
            byte[] vcDocument;
            try {
                vcDocument = vcResult.getCredential().toString().getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                log.error("Error converting VC to byte array", e);
                throw new CertifyException("VC_SERIALIZATION_FAILED");
            }

            String vcDocS = vcResult.getCredential().toString();
            log.info("Signed VC document: {}", vcDocS);

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

            try {
                Query nativeQuery = entityManager.createNativeQuery(insertSql);
                nativeQuery.setParameter(1, statusListCredential.getId());
                nativeQuery.setParameter(2, statusListCredential.getCapacity());

                int rowsInserted = nativeQuery.executeUpdate();

                log.info("Successfully initialized {} available indices for status list: {}", rowsInserted, statusListCredential.getId());

            } catch (Exception e) {
                if (entityManager.getTransaction().isActive()) {
                    entityManager.getTransaction().rollback();
                }
                throw e;
            } finally {
                entityManager.close();
            }

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
        Optional<StatusListCredential> existingStatusList = findSuitableStatusList(statusPurpose);

        if (existingStatusList.isPresent()) {
            log.info("suitable status list found, returning the existing one");
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
            // Prepare signer settings
            Map<String, String> signerSettings = new HashMap<>();
            signerSettings.put(Constants.APPLICATION_ID, CertifyIssuanceServiceImpl.keyChooser.get(vcSignAlgorithm).getFirst());
            signerSettings.put(Constants.REFERENCE_ID, CertifyIssuanceServiceImpl.keyChooser.get(vcSignAlgorithm).getLast());

            // Remove existing proof if present before re-signing
            JSONObject vcDocument = new JSONObject(vcDocumentJson);
            if (vcDocument.has("proof")) {
                vcDocument.remove("proof");
            }

            // Update validFrom timestamp to current time
            vcDocument.put("validFrom", new Date().toInstant().toString());

            // Sign the updated VC
            VCResult<?> vcResult = vcSigner.attachSignature(vcDocument.toString(), signerSettings);

            if (vcResult.getCredential() == null) {
                log.error("Failed to re-sign status list VC - vcResult.getCredential() returned null");
                throw new CertifyException("VC_RESIGNATION_FAILED");
            }

            String resignedVcDocument = vcResult.getCredential().toString();
            log.debug("Successfully re-signed status list credential");

            return resignedVcDocument;

        } catch (Exception e) {
            log.error("Error re-signing status list credential", e);
            throw new CertifyException("VC_RESIGNATION_FAILED");
        }
    }
}