package io.mosip.certify.services;

import io.mosip.certify.entity.CredentialStatus;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class StatusListService {

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;
    
    @Autowired
    private CredentialStatusRepository credentialStatusRepository;

    /**
     * Create a new status list credential
     * @param issuerId The ID of the issuer
     * @param statusPurpose The purpose of the status list (e.g., "revocation", "suspension")
     * @param userName The user creating the status list
     * @return The created StatusListCredential
     */
    @Transactional
    public StatusListCredential createStatusListCredential(String issuerId, String statusPurpose, String userName) {
        StatusListCredential statusList = new StatusListCredential();
        statusList.setId(UUID.randomUUID().toString());
        statusList.setIssuerId(issuerId);
        statusList.setStatusPurpose(statusPurpose);
        statusList.setEncodedList(Base64.getEncoder().encodeToString(new byte[1])); // Initialize with empty list
        statusList.setListSize(0);
        statusList.setValidFrom(LocalDateTime.now());
        statusList.setCreatedBy(userName);
        statusList.setCreatedTimes(LocalDateTime.now());
        statusList.setIsDeleted(false);
        
        return statusListCredentialRepository.save(statusList);
    }

    /**
     * Get a status list credential by issuer ID and status purpose
     * @param issuerId The ID of the issuer
     * @param statusPurpose The purpose of the status list
     * @return An Optional containing the StatusListCredential if found
     */
    public Optional<StatusListCredential> getStatusListCredential(String issuerId, String statusPurpose) {
        return statusListCredentialRepository.findByIssuerIdAndStatusPurpose(issuerId, statusPurpose);
    }

    /**
     * Get or create a status list credential
     * @param issuerId The ID of the issuer
     * @param statusPurpose The purpose of the status list
     * @param userName The user creating the status list if needed
     * @return The StatusListCredential
     */
    @Transactional
    public StatusListCredential getOrCreateStatusListCredential(String issuerId, String statusPurpose, String userName) {
        Optional<StatusListCredential> optionalStatusList = getStatusListCredential(issuerId, statusPurpose);
        return optionalStatusList.orElseGet(() -> createStatusListCredential(issuerId, statusPurpose, userName));
    }

    /**
     * Update the status list bitstring
     * @param issuerId The ID of the issuer
     * @param statusPurpose The purpose of the status list
     * @param userName The user updating the status list
     * @return The updated StatusListCredential
     */
    @Transactional
    public StatusListCredential updateStatusListBitstring(String issuerId, String statusPurpose, String userName) {
        // Get the status list credential
        StatusListCredential statusList = getOrCreateStatusListCredential(issuerId, statusPurpose, userName);
        
        // Get all credential statuses for this issuer and purpose
        List<CredentialStatus> statuses = credentialStatusRepository.findByIssuerIdAndStatusPurpose(issuerId, statusPurpose);
        
        // Find the maximum index to determine the bitstring size
        long maxIndex = statuses.stream()
                .mapToLong(CredentialStatus::getStatusListIndex)
                .max()
                .orElse(0);
        
        // Create a bitstring with the appropriate size (add some buffer)
        int bitstringSize = (int) (maxIndex / 8) + 1;
        byte[] bitstring = new byte[bitstringSize];
        
        // Set the bits for revoked credentials
        for (CredentialStatus status : statuses) {
            if ("revoked".equals(status.getCredentialStatus())) {
                int byteIndex = (int) (status.getStatusListIndex() / 8);
                int bitIndex = (int) (status.getStatusListIndex() % 8);
                bitstring[byteIndex] |= (1 << bitIndex);
            }
        }
        
        // Update the status list credential
        statusList.setEncodedList(Base64.getEncoder().encodeToString(bitstring));
        statusList.setListSize((int) maxIndex + 1);
        statusList.setUpdatedAt(LocalDateTime.now());
        statusList.setUpdatedBy(userName);
        statusList.setUpdatedTimes(LocalDateTime.now());
        
        return statusListCredentialRepository.save(statusList);
    }

    /**
     * Check if a credential is revoked in the status list
     * @param statusListCredential The status list credential URL
     * @param statusListIndex The index in the status list
     * @return true if the credential is revoked, false otherwise
     */
    public boolean isCredentialRevoked(String statusListCredential, long statusListIndex) {
        // Extract the issuer ID and status purpose from the status list credential URL
        // This is a simplification - in a real implementation, you might need to parse the URL
        String[] parts = statusListCredential.split("/");
        String issuerId = parts[parts.length - 2];
        String statusPurpose = parts[parts.length - 1];
        
        Optional<StatusListCredential> optionalStatusList = getStatusListCredential(issuerId, statusPurpose);
        if (optionalStatusList.isPresent()) {
            StatusListCredential statusList = optionalStatusList.get();
            byte[] bitstring = Base64.getDecoder().decode(statusList.getEncodedList());
            
            int byteIndex = (int) (statusListIndex / 8);
            int bitIndex = (int) (statusListIndex % 8);
            
            // Check if the bit is set
            return byteIndex < bitstring.length && (bitstring[byteIndex] & (1 << bitIndex)) != 0;
        }
        
        return false;
    }

    /**
     * Get the next available index in the status list
     * @param issuerId The ID of the issuer
     * @param statusPurpose The purpose of the status list
     * @return The next available index
     */
    public long getNextAvailableIndex(String issuerId, String statusPurpose) {
        Optional<StatusListCredential> optionalStatusList = getStatusListCredential(issuerId, statusPurpose);
        if (optionalStatusList.isPresent()) {
            return optionalStatusList.get().getListSize();
        } else {
            return 0;
        }
    }
}