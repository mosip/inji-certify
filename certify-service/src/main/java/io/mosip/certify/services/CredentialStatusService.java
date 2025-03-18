package io.mosip.certify.services;

import io.mosip.certify.entity.CredentialStatus;
import io.mosip.certify.repository.CredentialStatusRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class CredentialStatusService {

    @Autowired
    private CredentialStatusRepository credentialStatusRepository;

    /**
     * Create a new credential status entry
     * @param credentialId The ID of the credential
     * @param issuerId The ID of the issuer
     * @param statusListIndex The index in the status list
     * @param statusListCredential The URL of the status list credential
     * @param statusPurpose The purpose of the status (e.g., "revocation", "suspension")
     * @param userName The user creating the entry
     * @return The created CredentialStatus
     */
    @Transactional
    public CredentialStatus createCredentialStatus(String credentialId, String issuerId, 
                                                  Long statusListIndex, String statusListCredential, 
                                                  String statusPurpose, String userName) {
        CredentialStatus status = new CredentialStatus();
        status.setId(UUID.randomUUID().toString());
        status.setCredentialId(credentialId);
        status.setIssuerId(issuerId);
        status.setStatusListIndex(statusListIndex);
        status.setStatusListCredential(statusListCredential);
        status.setStatusPurpose(statusPurpose);
        status.setCredentialStatus("valid");
        status.setIssueDate(LocalDateTime.now());
        status.setCreatedBy(userName);
        status.setCreatedTimes(LocalDateTime.now());
        status.setIsDeleted(false);
        
        return credentialStatusRepository.save(status);
    }

    /**
     * Get a credential status by credential ID
     * @param credentialId The ID of the credential
     * @return An Optional containing the CredentialStatus if found
     */
    public Optional<CredentialStatus> getCredentialStatusByCredentialId(String credentialId) {
        return credentialStatusRepository.findByCredentialId(credentialId);
    }

    /**
     * Get all credential statuses by issuer ID
     * @param issuerId The ID of the issuer
     * @return A list of CredentialStatus objects
     */
    public List<CredentialStatus> getCredentialStatusesByIssuerId(String issuerId) {
        return credentialStatusRepository.findByIssuerId(issuerId);
    }

    /**
     * Update the status of a credential
     * @param credentialId The ID of the credential
     * @param newStatus The new status value
     * @param reason The reason for the status change
     * @param userName The user updating the status
     * @return The updated CredentialStatus
     */
    @Transactional
    public CredentialStatus updateCredentialStatus(String credentialId, String newStatus, 
                                                 String reason, String userName) {
        Optional<CredentialStatus> optionalStatus = credentialStatusRepository.findByCredentialId(credentialId);
        if (optionalStatus.isPresent()) {
            CredentialStatus status = optionalStatus.get();
            status.setCredentialStatus(newStatus);
            
            if ("revoked".equals(newStatus)) {
                status.setRevocationTimestamp(LocalDateTime.now());
                status.setRevocationReason(reason);
            }
            
            status.setUpdatedBy(userName);
            status.setUpdatedTimes(LocalDateTime.now());
            
            return credentialStatusRepository.save(status);
        } else {
            throw new RuntimeException("Credential status not found for credentialId: " + credentialId);
        }
    }

    /**
     * Check if a credential is valid
     * @param credentialId The ID of the credential
     * @return true if the credential is valid, false otherwise
     */
    public boolean isCredentialValid(String credentialId) {
        Optional<CredentialStatus> optionalStatus = credentialStatusRepository.findByCredentialId(credentialId);
        return optionalStatus.map(status -> "valid".equals(status.getCredentialStatus())).orElse(false);
    }
}