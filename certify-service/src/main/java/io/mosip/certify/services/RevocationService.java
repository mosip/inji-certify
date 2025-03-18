package io.mosip.certify.services;

// import io.mosip.certify.core.constants.VCDMConstants;
import io.mosip.certify.core.dto.ResponseWrapper;
import io.mosip.certify.entity.CredentialStatus;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.exception.CredentialNotFoundException;
import io.mosip.certify.exception.RevocationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class RevocationService {

    @Autowired
    private CredentialStatusService credentialStatusService;
    
    @Autowired
    private StatusListService statusListService;
    
    @Value("${certify.revocation.baseUrl}")
    private String revocationBaseUrl;

    /**
     * Revoke a credential
     * @param credentialId The ID of the credential to revoke
     * @param reason The reason for revocation
     * @param userName The user performing the revocation
     * @return A response containing the revocation status
     * @throws RevocationException If there's an error during revocation
     */
    @Transactional
    public ResponseWrapper<Map<String, Object>> revokeCredential(String credentialId, String reason, String userName) {
        ResponseWrapper<Map<String, Object>> response = new ResponseWrapper<>();
        
        try {
            // Get the credential status
            Optional<CredentialStatus> optionalStatus = credentialStatusService.getCredentialStatusByCredentialId(credentialId);
            if (!optionalStatus.isPresent()) {
                throw new CredentialNotFoundException("Credential not found: " + credentialId);
            }
            
            CredentialStatus status = optionalStatus.get();
            
            // Check if the credential is already revoked
            if ("revoked".equals(status.getCredentialStatus())) {
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("status", "already_revoked");
                responseData.put("message", "Credential is already revoked");
                responseData.put("credentialId", credentialId);
                response.setResponse(responseData);
                return response;
            }
            
            // Update the credential status
            status = credentialStatusService.updateCredentialStatus(credentialId, "revoked", reason, userName);
            
            // Update the status list bitstring
            StatusListCredential statusList = statusListService.updateStatusListBitstring(
                status.getIssuerId(), status.getStatusPurpose(), userName);
            
            // Prepare the response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("status", "revoked");
            responseData.put("message", "Credential successfully revoked");
            responseData.put("credentialId", credentialId);
            responseData.put("revocationTimestamp", status.getRevocationTimestamp());
            responseData.put("statusListCredential", status.getStatusListCredential());
            responseData.put("statusListIndex", status.getStatusListIndex());
            
            response.setResponse(responseData);
            return response;
            
        } catch (Exception e) {
            throw new RevocationException("Error revoking credential: " + e.getMessage(), e);
        }
    }

    /**
     * Verify the status of a credential
     * @param credentialId The ID of the credential to verify
     * @return A response containing the credential status
     * @throws RevocationException If there's an error during verification
     */
    public ResponseWrapper<Map<String, Object>> verifyCredentialStatus(String credentialId) {
        ResponseWrapper<Map<String, Object>> response = new ResponseWrapper<>();
        
        try {
            // Get the credential status
            Optional<CredentialStatus> optionalStatus = credentialStatusService.getCredentialStatusByCredentialId(credentialId);
            if (!optionalStatus.isPresent()) {
                throw new CredentialNotFoundException("Credential not found: " + credentialId);
            }
            
            CredentialStatus status = optionalStatus.get();
            
            // Check if the credential is revoked in the bitstring
            boolean isRevoked = statusListService.isCredentialRevoked(
                status.getStatusListCredential(), status.getStatusListIndex());
            
            // Prepare the response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("credentialId", credentialId);
            responseData.put("status", isRevoked ? "revoked" : "valid");
            responseData.put("statusListCredential", status.getStatusListCredential());
            responseData.put("statusListIndex", status.getStatusListIndex());
            
            if (isRevoked) {
                responseData.put("revocationTimestamp", status.getRevocationTimestamp());
                responseData.put("revocationReason", status.getRevocationReason());
            }
            
            response.setResponse(responseData);
            return response;
            
        } catch (Exception e) {
            throw new RevocationException("Error verifying credential status: " + e.getMessage(), e);
        }
    }

    /**
     * Generate the credentialStatus property for a verifiable credential
     * @param issuerId The ID of the issuer
     * @param statusPurpose The purpose of the status (e.g., "revocation", "suspension")
     * @param userName The user creating the credential
     * @return A map containing the credentialStatus property
     */
    @Transactional
    public Map<String, Object> generateCredentialStatusProperty(String issuerId, String statusPurpose, String userName) {
        try {
            // Get or create the status list credential
            StatusListCredential statusList = statusListService.getOrCreateStatusListCredential(issuerId, statusPurpose, userName);
            
            // Get the next available index
            long statusListIndex = statusListService.getNextAvailableIndex(issuerId, statusPurpose);
            
            // Construct the status list credential URL
            String statusListCredentialUrl = String.format("%s/issuers/%s/status-lists/%s", 
                revocationBaseUrl, issuerId, statusPurpose);
            
            // Create the credentialStatus property
            Map<String, Object> credentialStatus = new HashMap<>();
            credentialStatus.put("id", statusListCredentialUrl + "#" + statusListIndex);
            credentialStatus.put("type", "BitstringStatusListEntry");
            credentialStatus.put("statusPurpose", statusPurpose);
            credentialStatus.put("statusListIndex", String.valueOf(statusListIndex));
            credentialStatus.put("statusListCredential", statusListCredentialUrl);
            
            return credentialStatus;
            
        } catch (Exception e) {
            throw new RevocationException("Error generating credential status property: " + e.getMessage(), e);
        }
    }

    /**
     * Register a credential status in the system
     * @param credentialId The ID of the credential
     * @param issuerId The ID of the issuer
     * @param statusPurpose The purpose of the status
     * @param userName The user registering the credential
     * @return The created CredentialStatus
     * @throws RevocationException If there's an error during registration
     */
    @Transactional
    public CredentialStatus registerCredentialStatus(String credentialId, String issuerId, String statusPurpose, String userName) {
        try {
            // Check if the credential status already exists
            Optional<CredentialStatus> existingStatus = credentialStatusService.getCredentialStatusByCredentialId(credentialId);
            if (existingStatus.isPresent()) {
                return existingStatus.get();
            }
            
            // Get or create the status list credential
            StatusListCredential statusList = statusListService.getOrCreateStatusListCredential(issuerId, statusPurpose, userName);
            
            // Get the next available index
            long statusListIndex = statusListService.getNextAvailableIndex(issuerId, statusPurpose);
            
            // Construct the status list credential URL
            String statusListCredentialUrl = String.format("%s/issuers/%s/status-lists/%s", 
                revocationBaseUrl, issuerId, statusPurpose);
            
            // Create the credential status
            CredentialStatus status = credentialStatusService.createCredentialStatus(
                credentialId, issuerId, statusListIndex, statusListCredentialUrl, statusPurpose, userName);
            
            // Update the status list size
            statusList.setListSize(statusList.getListSize() + 1);
            statusList.setUpdatedAt(LocalDateTime.now());
            statusList.setUpdatedBy(userName);
            statusList.setUpdatedTimes(LocalDateTime.now());
            
            return status;
            
        } catch (Exception e) {
            throw new RevocationException("Error registering credential status: " + e.getMessage(), e);
        }
    }

    /**
     * Generate a status list credential document
     * @param issuerId The ID of the issuer
     * @param statusPurpose The purpose of the status list
     * @return A map containing the status list credential document
     * @throws RevocationException If there's an error generating the document
     */
    public Map<String, Object> generateStatusListCredentialDocument(String issuerId, String statusPurpose) {
        try {
            // Get the status list credential
            Optional<StatusListCredential> optionalStatusList = statusListService.getStatusListCredential(issuerId, statusPurpose);
            if (!optionalStatusList.isPresent()) {
                throw new RevocationException("Status list credential not found for issuer: " + issuerId + " and purpose: " + statusPurpose);
            }
            
            StatusListCredential statusList = optionalStatusList.get();
            
            // Construct the status list credential URL
            String statusListCredentialUrl = String.format("%s/issuers/%s/status-lists/%s", 
                revocationBaseUrl, issuerId, statusPurpose);
            
            // Create the status list credential document
            Map<String, Object> document = new HashMap<>();
            document.put("@context", new String[] {
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            });
            document.put("id", statusListCredentialUrl);
            document.put("type", new String[] {"VerifiableCredential", "StatusList2021Credential"});
            document.put("issuer", issuerId);
            document.put("issuanceDate", statusList.getCreatedAt().toString());
            
            Map<String, Object> credentialSubject = new HashMap<>();
            credentialSubject.put("id", statusListCredentialUrl + "#list");
            credentialSubject.put("type", "StatusList2021");
            credentialSubject.put("statusPurpose", statusPurpose);
            credentialSubject.put("encodedList", statusList.getEncodedList());
            
            document.put("credentialSubject", credentialSubject);
            
            return document;
            
        } catch (Exception e) {
            throw new RevocationException("Error generating status list credential document: " + e.getMessage(), e);
        }
    }

    /**
     * Suspend a credential (temporary revocation)
     * @param credentialId The ID of the credential to suspend
     * @param reason The reason for suspension
     * @param userName The user performing the suspension
     * @return A response containing the suspension status
     * @throws RevocationException If there's an error during suspension
     */
    @Transactional
    public ResponseWrapper<Map<String, Object>> suspendCredential(String credentialId, String reason, String userName) {
        ResponseWrapper<Map<String, Object>> response = new ResponseWrapper<>();
        
        try {
            // Get the credential status
            Optional<CredentialStatus> optionalStatus = credentialStatusService.getCredentialStatusByCredentialId(credentialId);
            if (!optionalStatus.isPresent()) {
                throw new CredentialNotFoundException("Credential not found: " + credentialId);
            }
            
            CredentialStatus status = optionalStatus.get();
            
            // Check if the credential is already suspended or revoked
            if ("suspended".equals(status.getCredentialStatus()) || "revoked".equals(status.getCredentialStatus())) {
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("status", "already_" + status.getCredentialStatus());
                responseData.put("message", "Credential is already " + status.getCredentialStatus());
                responseData.put("credentialId", credentialId);
                response.setResponse(responseData);
                return response;
            }
            
            // Update the credential status
            status = credentialStatusService.updateCredentialStatus(credentialId, "suspended", reason, userName);
            
            // Update the status list bitstring
            StatusListCredential statusList = statusListService.updateStatusListBitstring(
                status.getIssuerId(), status.getStatusPurpose(), userName);
            
            // Prepare the response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("status", "suspended");
            responseData.put("message", "Credential successfully suspended");
            responseData.put("credentialId", credentialId);
            responseData.put("suspensionTimestamp", status.getRevocationTimestamp());
            responseData.put("statusListCredential", status.getStatusListCredential());
            responseData.put("statusListIndex", status.getStatusListIndex());
            
            response.setResponse(responseData);
            return response;
            
        } catch (Exception e) {
            throw new RevocationException("Error suspending credential: " + e.getMessage(), e);
        }
    }

    /**
     * Reactivate a suspended credential
     * @param credentialId The ID of the credential to reactivate
     * @param userName The user performing the reactivation
     * @return A response containing the reactivation status
     * @throws RevocationException If there's an error during reactivation
     */
    @Transactional
    public ResponseWrapper<Map<String, Object>> reactivateCredential(String credentialId, String userName) {
        ResponseWrapper<Map<String, Object>> response = new ResponseWrapper<>();
        
        try {
            // Get the credential status
            Optional<CredentialStatus> optionalStatus = credentialStatusService.getCredentialStatusByCredentialId(credentialId);
            if (!optionalStatus.isPresent()) {
                throw new CredentialNotFoundException("Credential not found: " + credentialId);
            }
            
            CredentialStatus status = optionalStatus.get();
            
            // Check if the credential is suspended
            if (!"suspended".equals(status.getCredentialStatus())) {
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("status", "not_suspended");
                responseData.put("message", "Credential is not suspended");
                responseData.put("credentialId", credentialId);
                response.setResponse(responseData);
                return response;
            }
            
            // Update the credential status
            status = credentialStatusService.updateCredentialStatus(credentialId, "valid", "Reactivated", userName);
            
            // Update the status list bitstring
            StatusListCredential statusList = statusListService.updateStatusListBitstring(
                status.getIssuerId(), status.getStatusPurpose(), userName);
            
            // Prepare the response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("status", "reactivated");
            responseData.put("message", "Credential successfully reactivated");
            responseData.put("credentialId", credentialId);
            responseData.put("reactivationTimestamp", status.getUpdatedTimes());
            responseData.put("statusListCredential", status.getStatusListCredential());
            responseData.put("statusListIndex", status.getStatusListIndex());
            
            response.setResponse(responseData);
            return response;
            
        } catch (Exception e) {
            throw new RevocationException("Error reactivating credential: " + e.getMessage(), e);
        }
    }
}