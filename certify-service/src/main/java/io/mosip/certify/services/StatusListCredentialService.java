package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.BitStringUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.certify.vcsigners.VCSigner;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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
            String statusListId = domainUrl + "/status-list-credentials/" + UUID.randomUUID().toString();

            // Create the template data for the status list VC
            JSONObject statusListData = new JSONObject();
            statusListData.put("statusPurpose", statusPurpose);
            statusListData.put("statusListId", statusListId);
            statusListData.put("issuer", issuerId);

            // Create empty encoded list (all 0s)
            String encodedList = bitStringStatusListService.createEmptyEncodedList(defaultCapacity);
            statusListData.put("encodedList", encodedList);

            // Format the status list credential using VCFormatter
            Map<String, Object> templateParams = new HashMap<>();
            templateParams.put(Constants.TEMPLATE_NAME, statusListTemplateName);
            templateParams.put(Constants.ISSUER_URI, issuerId);

            String unsignedVC = vcFormatter.format(statusListData, templateParams);

            // Sign the status list credential
            Map<String, String> signerSettings = new HashMap<>();
            signerSettings.put(Constants.APPLICATION_ID, CertifyIssuanceServiceImpl.keyChooser.get(vcSignAlgorithm).getFirst());
            signerSettings.put(Constants.REFERENCE_ID, CertifyIssuanceServiceImpl.keyChooser.get(vcSignAlgorithm).getLast());

            // Attach signature to the VC
            VCResult<?> vcResult = vcSigner.attachSignature(unsignedVC, signerSettings);

            if (vcResult.getCredential() == null) {
                log.error("Failed to generate status list VC");
                throw new CertifyException("VC_ISSUANCE_FAILED");
            }

            // Convert to byte array for storage
            byte[] vcDocument = vcResult.getCredential().toString().getBytes();

            // Create and save the status list credential entity
            StatusListCredential statusListCredential = new StatusListCredential();
            statusListCredential.setId(statusListId);
            statusListCredential.setVcDocument(vcDocument);
            statusListCredential.setCredentialType("BitstringStatusListCredential");
            statusListCredential.setStatusPurpose(statusPurpose);
            statusListCredential.setCapacity(defaultCapacity);
            statusListCredential.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
            statusListCredential.setCreatedDtimes(LocalDateTime.now());

            // Save to database
            return statusListCredentialRepository.save(statusListCredential);

        } catch (Exception e) {
            log.error("Error generating status list credential", e);
            throw new CertifyException("STATUS_LIST_GENERATION_FAILED");
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
            return existingStatusList.get();
        }

        // No suitable status list found, generate a new one
        log.info("No suitable status list found, generating a new one");
        return generateStatusListCredential(statusPurpose);
    }

    /**
     * Find next available index in the status list
     *
     * @param statusListId the ID of the status list
     * @return the next available index, or -1 if the list is full
     */
    public long findNextAvailableIndex(String statusListId) {
        Optional<StatusListCredential> statusListOpt = statusListCredentialRepository.findById(statusListId);

        if (statusListOpt.isEmpty()) {
            log.error("Status list not found with ID: {}", statusListId);
            throw new CertifyException("STATUS_LIST_NOT_FOUND");
        }

        StatusListCredential statusList = statusListOpt.get();
        if (statusList.getCredentialStatus() == StatusListCredential.CredentialStatus.FULL) {
            log.info("Status list is full: {}", statusListId);
            return -1;
        }

        // Get the status list data and find next available index
        JsonLDObject statusListVC = deserializeVC(statusList.getVcDocument());
        String encodedList = getEncodedListFromVC(statusListVC);

        long nextIndex = bitStringStatusListService.findNextAvailableIndex(encodedList);

        // Check if the list is now full after this allocation
        if (nextIndex == -1 || nextIndex >= statusList.getCapacity() - 1) {
            statusList.setCredentialStatus(StatusListCredential.CredentialStatus.FULL);
            statusListCredentialRepository.save(statusList);

            if (nextIndex == -1) {
                return -1; // No available index found
            }
        }

        return nextIndex;
    }

    /**
     * Update the status at a specific index in the status list
     *
     * @param statusListId the ID of the status list
     * @param index the index to update
     * @param isRevoked true if the credential is revoked, false otherwise
     * @return updated StatusListCredential
     */
    @Transactional
    public StatusListCredential updateStatusAtIndex(String statusListId, long index, boolean isRevoked) {
        Optional<StatusListCredential> statusListOpt = statusListCredentialRepository.findById(statusListId);

        if (statusListOpt.isEmpty()) {
            log.error("Status list not found with ID: {}", statusListId);
            throw new CertifyException("STATUS_LIST_NOT_FOUND");
        }

        StatusListCredential statusList = statusListOpt.get();

        // Get the status list data
        JsonLDObject statusListVC = deserializeVC(statusList.getVcDocument());
        String encodedList = getEncodedListFromVC(statusListVC);

        // Update the bit at the specified index
        String updatedEncodedList = bitStringStatusListService.updateStatusAtIndex(encodedList, index, isRevoked);

        // Create updated VC with new encodedList
        JSONObject statusListData = new JSONObject();
        statusListData.put("statusPurpose", statusList.getStatusPurpose());
        statusListData.put("statusListId", statusListId);
        statusListData.put("issuer", issuerId);
        statusListData.put("encodedList", updatedEncodedList);

        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put(Constants.TEMPLATE_NAME, statusListTemplateName);
        templateParams.put(Constants.ISSUER_URI, issuerId);

        String unsignedVC = vcFormatter.format(statusListData, templateParams);

        // Sign the updated VC
        Map<String, String> signerSettings = new HashMap<>();
        signerSettings.put(Constants.APPLICATION_ID, CertifyIssuanceServiceImpl.keyChooser.get("Ed25519Signature2020").getFirst());
        signerSettings.put(Constants.REFERENCE_ID, CertifyIssuanceServiceImpl.keyChooser.get("Ed25519Signature2020").getLast());

        VCResult<?> vcResult = vcSigner.attachSignature(unsignedVC, signerSettings);

        if (vcResult.getCredential() == null) {
            log.error("Failed to update status list VC");
            throw new CertifyException("VC_ISSUANCE_FAILED");
        }

        // Update the entity with new VC document
        statusList.setVcDocument(vcResult.getCredential().toString().getBytes());
        statusList.setUpdatedDtimes(LocalDateTime.now());

        return statusListCredentialRepository.save(statusList);
    }

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
}