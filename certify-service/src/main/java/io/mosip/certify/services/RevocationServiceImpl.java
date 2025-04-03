package io.mosip.certify.services;

import io.mosip.certify.core.dto.*;
import io.mosip.certify.entity.LedgerIssuanceTable;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.exception.CredentialIssuanceException;
import io.mosip.certify.exception.CredentialNotFoundException;
import io.mosip.certify.exception.RevocationException;
import io.mosip.certify.repository.LedgerIssuanceTableRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.services.RevocationService;
import io.mosip.certify.utils.BitStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
public class RevocationServiceImpl implements RevocationService {

    @Autowired
    private CertifyIssuanceServiceImpl certifyIssuanceService;

    @Autowired
    private LedgerIssuanceTableRepository ledgerRepository;

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    private BitStringStatusListService bitStringStatusListService;

//    /**
//     * Issue a credential with status tracking capabilities
//     * @param request The credential issuance request
//     * @return The issued credential response
//     * @throws CredentialIssuanceException if credential issuance fails
//     */
//    @Override
//    @Transactional
//    public CredentialIssuanceResponse issueCredential(CredentialIssuanceRequest request) throws CredentialIssuanceException {
//        try {
//            // Generate a unique status list index
//            String statusListIndex = String.valueOf(Math.abs(UUID.randomUUID().hashCode()));
//
//            // Get or create status list credential URL
//            String statusListCredentialUrl = getOrCreateStatusListCredential(request.getIssuerId());
//
//            // Add status tracking info to the request
//            // Here you would enhance your existing credential request with status info
//
//            // Issue the credential using existing service
//            CredentialResponse credentialResponse = certifyIssuanceService.issueCredential(request);
//
//            // After successful issuance, save to ledger
//            LedgerIssuanceTable ledgerEntry = new LedgerIssuanceTable();
//            ledgerEntry.setCredentialId(credentialResponse.getCredentialId());
//            ledgerEntry.setIssuerId(request.getIssuerId());
//            ledgerEntry.setStatusListIndex(statusListIndex);
//            ledgerEntry.setStatusListCredential(statusListCredentialUrl);
//            ledgerEntry.setStatusPurpose("revocation");
//            ledgerEntry.setCredentialStatus("valid");
//            ledgerEntry.setIssueDate(LocalDateTime.now());
//
//            if (request.getExpirationDate() != null) {
//                ledgerEntry.setExpirationDate(request.getExpirationDate());
//            }
//
//            ledgerEntry.setHolderInfo(request.getHolderInfo());
//            ledgerEntry.setCredentialType(request.getCredentialType());
//
//            ledgerRepository.save(ledgerEntry);
//
//            return credentialResponse;
//        } catch (Exception e) {
//            throw new CredentialIssuanceException("Error issuing credential with status tracking: " + e.getMessage(), e);
//        }
//    }

    /**
     * Fetch credential status information based on filters
     * @param request The credential fetch request containing filters
     * @return The credential status information
     * @throws CredentialNotFoundException if the credential cannot be found
     */
    @Override
    public CredentialFetchResponse fetchCredential(CredentialFetchRequest request) throws CredentialNotFoundException {
        try {
            List<LedgerIssuanceTable> credentials = findCredentialsByFilters(request);

            if (credentials.isEmpty()) {
                throw new CredentialNotFoundException("No credentials found matching the provided filters");
            }

            LedgerIssuanceTable credential = credentials.get(0);

            CredentialFetchResponse response = new CredentialFetchResponse();
//            response.setCredentialId(credential.getCredentialId());
            response.setStatusPurpose(credential.getStatusPurpose());
            response.setStatusListIndex(credential.getStatusListIndex().toString());
            response.setStatusListCredential(credential.getStatusListCredential());
//            response.setCredentialStatus(credential.getCredentialStatus());
//            response.setRevocationReason(credential.getRevocationReason());
//            response.setRevocationTimestamp(credential.getRevocationTimestamp());
//            response.setIssueDate(credential.getIssueDate());
//            response.setExpirationDate(credential.getExpirationDate());

            return response;
        } catch (CredentialNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialNotFoundException("Error fetching credential: " + e.getMessage(), e);
        }
    }

    /**
     * Helper method to find credentials based on filters
     * @param request The credential fetch request containing filters
     * @return List of matching credentials
     */
    private List<LedgerIssuanceTable> findCredentialsByFilters(CredentialFetchRequest request) {
        if (request.getCredentialId() != null && !request.getCredentialId().isEmpty()) {
            // If credential ID is provided, use that as the primary search parameter
            Optional<LedgerIssuanceTable> credentialOpt = ledgerRepository.findByCredentialId(request.getCredentialId());
            return credentialOpt.map(Collections::singletonList).orElseGet(Collections::emptyList);
        }

        List<LedgerIssuanceTable> results = new ArrayList<>();

        // Example implementation using custom repository methods
        if (request.getIssuerId() != null && !request.getIssuerId().isEmpty()) {
            results = ledgerRepository.findByIssuerId(request.getIssuerId());
        }

        return results;
    }


    /**
     * Revoke a credential
     * @param request The revocation request with credential ID and reason
     * @return Success message if revocation is successful
     * @throws RevocationException if revocation fails
     */
    @Override
    @Transactional
    public CredentialRevocationResponse revokeCredential(CredentialRevocationRequest request) throws RevocationException, CredentialNotFoundException {
        try {
            // Find the credential to revoke
            Optional<LedgerIssuanceTable> credentialOptional = ledgerRepository.findByCredentialId(request.getCredentialId());

            if (!credentialOptional.isPresent()) {
                throw new CredentialNotFoundException("Credential not found with ID: " + request.getCredentialId());
            }

            LedgerIssuanceTable credential = credentialOptional.get();

            // Check if already revoked
            if ("revoked".equals(credential.getCredentialStatus())) {
                throw new RevocationException("Credential already revoked: " + request.getCredentialId());
            }

            // Update the credential status
            credential.setCredentialStatus("revoked");
            credential.setStatusPurpose("revocation");
            credential.setRevocationTimestamp(LocalDateTime.now());
            credential.setRevocationReason(request.getRevocationReason());

            if (request.getRevocationProof() != null) {
                credential.setRevocationProof(request.getRevocationProof().getJwt());
            }

            // Update the status list credential
            bitStringStatusListService.updateStatusListBitstring(credential);

            // Save the updated credential status
            ledgerRepository.save(credential);

            CredentialRevocationResponse response = new CredentialRevocationResponse();
            response.message = "Credential successfully revoked";
            return response;
        } catch (CredentialNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new RevocationException("Error revoking credential: " + e.getMessage(), e);
        }
    }

}