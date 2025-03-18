package io.mosip.certify.services;

import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.mosip.certify.core.dto.CredentialIssuanceDTO;
import io.mosip.certify.core.dto.CredentialIssuanceResponseDTO;
import io.mosip.certify.entity.CredentialStatus;
import io.mosip.certify.exception.CredentialIssuanceException;
import io.mosip.certify.repository.CredentialStatusRepository;
import io.mosip.certify.core.dto.ResponseWrapper;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class CredentialIssuanceService {

    @Autowired
    private RevocationService revocationService;
    
    @Autowired
    private CredentialStatusRepository credentialStatusRepository;

    /**
     * Issues a new verifiable credential and registers its status
     * 
     * @param issuanceDTO the credential issuance request data
     * @return ResponseWrapper containing the issuance response
     */
    @Transactional
    public ResponseWrapper<CredentialIssuanceResponseDTO> issueCredential(CredentialIssuanceDTO issuanceDTO) {
        try {
            log.info("Initiating credential issuance for credentialId: {}", issuanceDTO.getCredentialId());
            
            // Check if credential with same ID already exists
            if (credentialStatusRepository.existsById(issuanceDTO.getCredentialId())) {
                throw new CredentialIssuanceException("Credential with ID " + issuanceDTO.getCredentialId() + " already exists");
            }
            
            // Generate credential status property according to W3C VC Data Model 2.0
            Map<String, Object> credentialStatusProperty = revocationService.generateCredentialStatusProperty(
                    issuanceDTO.getIssuerId(), 
                    issuanceDTO.getStatusPurpose(), 
                    issuanceDTO.getUserName());
            
            // Register the credential status in the system
            CredentialStatus registeredStatus = revocationService.registerCredentialStatus(
                    issuanceDTO.getCredentialId(),
                    issuanceDTO.getIssuerId(),
                    issuanceDTO.getStatusPurpose(),
                    issuanceDTO.getUserName());
            
            // Create response DTO
            CredentialIssuanceResponseDTO responseDTO = new CredentialIssuanceResponseDTO();
            responseDTO.setCredentialId(issuanceDTO.getCredentialId());
            responseDTO.setStatus("valid");
            responseDTO.setIssueDate(LocalDateTime.now());
            responseDTO.setCredentialStatus(credentialStatusProperty);
            
            // Create and return response wrapper
            ResponseWrapper<CredentialIssuanceResponseDTO> response = new ResponseWrapper<>();
            response.setResponse(responseDTO);
        
            log.info("Credential issuance successful for credentialId: {}", issuanceDTO.getCredentialId());
            
            return response;
        } catch (Exception e) {
            log.error("Error during credential issuance: {}", e.getMessage(), e);
            throw new CredentialIssuanceException("Failed to issue credential: " + e.getMessage(), e);
        }
    }
}