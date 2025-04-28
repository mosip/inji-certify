package io.mosip.certify.services;

import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.entity.LedgerIssuanceTable;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.repository.LedgerIssuanceTableRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@Slf4j
@Service
public class BitStringStatusListService {

    private static final int MINIMUM_BITSTRING_SIZE = 131072; // 16 KB
    private static final int STATUS_SIZE = 1; // Default status size as per spec

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    private LedgerIssuanceTableRepository ledgerIssuanceTableRepository;

    /**
     * Generate Status List Credential as per Section 3.3 Bitstring Generation Algorithm
     *
     * @param issuerId Issuer identifier
     * @param statusPurpose Purpose of the status list (e.g., "revocation")
     * @return URL of the generated status list credential
     */
    public String generateStatusListCredential(String issuerId, String statusPurpose, String domainUrl) {

        Optional<StatusListCredential> existingList = statusListCredentialRepository
                .findByIssuerIdAndStatusPurpose(issuerId, statusPurpose);
        log.info("ExistingList: {}", existingList);

        if (existingList.isPresent()) {
            return existingList.get().getId();
        }
        // Initialize bitstring of minimum 16 KB size, all bits set to 0
        byte[] bitstring = new byte[MINIMUM_BITSTRING_SIZE];

        // Find all issued credentials for this issuer and status purpose
        List<LedgerIssuanceTable> issuedCredentials = ledgerIssuanceTableRepository
                .findByIssuerIdAndStatusPurpose(issuerId, statusPurpose);

        // Set status for each credential
        for (LedgerIssuanceTable credential : issuedCredentials) {
            int index = (int) (credential.getStatusListIndex() * STATUS_SIZE);
            if (index < bitstring.length) {
                // Set the appropriate bit based on credential status
                bitstring[index] = credential.getCredentialStatus().equals("revoked") ? (byte) 1 : (byte) 0;
            }
        }

        // Compress bitstring using GZIP
        String compressedBitstring = compressAndEncodebitstring(bitstring);

        // Create or update status list credential
        // String statusListId = domainUrl
        StatusListCredential statusList = new StatusListCredential();
        statusList.setId(domainUrl);
        statusList.setIssuerId(issuerId);
        statusList.setStatusPurpose(statusPurpose);
        statusList.setEncodedList(compressedBitstring);
        statusList.setListSize(issuedCredentials.size());
        statusList.setValidFrom(LocalDateTime.now());

        statusListCredentialRepository.save(statusList);

        return domainUrl;
    }

    /**
     * Validate Credential Status as per Section 3.2 Validate Algorithm
     *
     * @param statusListCredentialUrl URL of the status list credential
     * @param statusListIndex Index of the credential in the status list
     * @param statusPurpose Purpose of the status (e.g., "revocation")
     * @return Validation result
     */
    public boolean validateCredentialStatus(String statusListCredentialUrl, long statusListIndex, String statusPurpose) {
        // Retrieve status list credential
        Optional<StatusListCredential> statusListOptional =
                statusListCredentialRepository.findById(statusListCredentialUrl);

        if (statusListOptional.isEmpty()) {
            throw new RuntimeException("Status List Credential not found");
        }

        StatusListCredential statusList = statusListOptional.get();

        // Verify status purpose matches
        if (!statusPurpose.equals(statusList.getStatusPurpose())) {
            throw new RuntimeException("Status Purpose Mismatch");
        }

        // Expand compressed bitstring
        byte[] uncompressedBitstring = decompressAndDecodebitstring(statusList.getEncodedList());

        // Validate list length (minimum 131,072 entries)
        if (uncompressedBitstring.length / STATUS_SIZE < 131_072) {
            throw new RuntimeException("Status List Length Too Short");
        }

        Optional<LedgerIssuanceTable> issuanceRecord = ledgerIssuanceTableRepository.findByStatusListIndex(statusListIndex);
        if (issuanceRecord.isEmpty()) {
            throw new RuntimeException("Credential has not been issued for the provided index");
        }

        // Check credential status
        int index = (int) (statusListIndex * STATUS_SIZE);
        if (index >= uncompressedBitstring.length) {
            throw new RuntimeException("Status List Index Out of Range");
        }

        // Return true if bit is 0 (valid), false if bit is 1 (revoked/invalid)
        return uncompressedBitstring[index] == 0;
    }

    /**
     * Compress bitstring using GZIP and encode using Base64url
     *
     * @param bitstring Uncompressed bitstring
     * @return Compressed and Base64url encoded bitstring
     */
    private String compressAndEncodebitstring(byte[] bitstring) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzipOS = new GZIPOutputStream(baos)) {
            gzipOS.write(bitstring);
            gzipOS.close();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
        } catch (IOException e) {
            log.error("Error compressing bitstring", e);
            throw new RuntimeException("Bitstring Compression Failed", e);
        }
    }

    /**
     * Decompress bitstring from Base64url and GZIP
     *
     * @param compressedBitstring Compressed and Base64url encoded bitstring
     * @return Uncompressed bitstring
     */
    private byte[] decompressAndDecodebitstring(String compressedBitstring) {
        try {
            byte[] compressedBytes = Base64.getUrlDecoder().decode(compressedBitstring);
            try (ByteArrayInputStream bais = new ByteArrayInputStream(compressedBytes);
                 GZIPInputStream gzipIS = new GZIPInputStream(bais);
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = gzipIS.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                return baos.toByteArray();
            }
        } catch (IOException e) {
            log.error("Error decompressing bitstring", e);
            throw new RuntimeException("Bitstring Decompression Failed", e);
        }
    }

    public void revokeCredential(String statusListCredentialUrl, long statusListIndex, String statusPurpose) {
        Optional<StatusListCredential> statusListOptional = statusListCredentialRepository.findById(statusListCredentialUrl);
        System.out.println("Status List Credential found: " + statusListOptional);
        if (statusListOptional.isEmpty()) {
            throw new RuntimeException("Status List Credential not found");
        }
    
        StatusListCredential statusList = statusListOptional.get();
        if (!statusPurpose.equals(statusList.getStatusPurpose())) {
            throw new RuntimeException("Status Purpose mismatch");
        }

        Optional<LedgerIssuanceTable> issuanceRecord = ledgerIssuanceTableRepository.findByStatusListIndex(statusListIndex);
        if (issuanceRecord.isEmpty()) {
            throw new RuntimeException("Credential has not been issued for the provided index");
        }
    
        byte[] bitstring = decompressAndDecodebitstring(statusList.getEncodedList());
        int index = (int) (statusListIndex * STATUS_SIZE);
    
        if (index >= bitstring.length) {
            throw new RuntimeException("Status List Index Out of Range");
        }
    
        bitstring[index] = 1; // Mark as revoked
        String updatedEncodedList = compressAndEncodebitstring(bitstring);
        statusList.setEncodedList(updatedEncodedList);
        statusList.setValidFrom(LocalDateTime.now());
    
        statusListCredentialRepository.save(statusList);
    }

    public void revokeCredentialV1(String hashedCredentialSubject) {
        Optional<LedgerIssuanceTable> issuanceRecordOptional = ledgerIssuanceTableRepository.findByCredentialSubjectHash(hashedCredentialSubject);
        if (issuanceRecordOptional.isEmpty()) {
            throw new RuntimeException("Credential has not been issued for the provided hash");
        }
    
        LedgerIssuanceTable ledgerIssuanceRecord = issuanceRecordOptional.get();
        
        String statusListCredentialUrl = ledgerIssuanceRecord.getStatusListCredential();
        long statusListIndex = ledgerIssuanceRecord.getStatusListIndex();
        String statusPurpose = ledgerIssuanceRecord.getStatusPurpose();
    
        revokeCredential(statusListCredentialUrl, statusListIndex, statusPurpose);
    }
    
}
