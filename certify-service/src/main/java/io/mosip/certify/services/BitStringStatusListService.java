package io.mosip.certify.services;

import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.entity.LedgerIssuanceTable;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.repository.LedgerIssuanceTableRepository;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.constants.ErrorConstants;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.zip.GZIPOutputStream;

@Slf4j
@Service
public class BitstringStatusListService {

    private static final int MINIMUM_LIST_ENTRIES = 131_072; // As per specification
    private static final int STATUS_SIZE = 1; // Default status size (1 bit)

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    private LedgerIssuanceTableRepository ledgerIssuanceTableRepository;

    /**
     * Generate a Bitstring Status List Credential
     *
     * @param issuerId The issuer's identifier
     * @param statusPurpose Purpose of the status list (e.g., "revocation")
     * @return URL of the generated status list credential
     */
    @Transactional
    public String generateStatusListCredential(String issuerId, String statusPurpose) {
        try {
            // Check if a status list credential already exists
            Optional<StatusListCredential> existingList = statusListCredentialRepository
                    .findByIssuerIdAndStatusPurpose(issuerId, statusPurpose);

            if (existingList.isPresent()) {
                return existingList.get().getId();
            }

            // Generate a new status list credential
            String statusListId = generateStatusListId(issuerId);

            // Generate initial bitstring (all zeros)
            byte[] initialBitstring = new byte[MINIMUM_LIST_ENTRIES / 8]; // 16 KB
            String encodedList = compressBitstring(initialBitstring);

            StatusListCredential statusList = new StatusListCredential();
            statusList.setId(statusListId);
            statusList.setIssuerId(issuerId);
            statusList.setStatusPurpose(statusPurpose);
            statusList.setEncodedList(encodedList);
            statusList.setListSize(MINIMUM_LIST_ENTRIES);
            statusList.setValidFrom(LocalDateTime.now());

            statusListCredentialRepository.save(statusList);

            return statusListId;
        } catch (Exception e) {
            log.error("Error generating status list credential", e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR);
        }
    }

    /**
     * Update the status of a credential in the status list
     *
     * @param statusListCredentialId The ID of the status list credential
     * @param statusListIndex Index of the credential in the list
     * @param status Status to set (0 or 1)
     */
    @Transactional
    public void updateStatusListCredential(String statusListCredentialId, long statusListIndex, int status) {
        try {
            // Retrieve the existing status list credential
            StatusListCredential statusListCredential = statusListCredentialRepository
                    .findById(statusListCredentialId)
//                    .orElseThrow(() -> new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND));
                    .orElseThrow(() -> new CertifyException("STATUS_LIST_NOT_FOUND"));

            // Decompress the existing list
            byte[] decompressedBitstring = decompressBitstring(statusListCredential.getEncodedList());

            // Update the specific bit
            updateBit(decompressedBitstring, statusListIndex, status);

            // Compress and save the updated bitstring
            String updatedEncodedList = compressBitstring(decompressedBitstring);
            statusListCredential.setEncodedList(updatedEncodedList);
            statusListCredentialRepository.save(statusListCredential);
        } catch (Exception e) {
            log.error("Error updating status list credential", e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR);
        }
    }

    /**
     * Validate the status of a credential
     *
     * @param statusListCredentialId ID of the status list credential
     * @param statusListIndex Index of the credential in the list
     * @return Status of the credential (true if valid, false if revoked/suspended)
     */
    @Transactional(readOnly = true)
    public boolean validateCredentialStatus(String statusListCredentialId, long statusListIndex) {
        try {
            // Retrieve the status list credential
            StatusListCredential statusListCredential = statusListCredentialRepository
                    .findById(statusListCredentialId)
//                    .orElseThrow(() -> new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND));
                    .orElseThrow(() -> new CertifyException("STATUS_LIST_NOT_FOUND"));

            // Decompress the bitstring
            byte[] decompressedBitstring = decompressBitstring(statusListCredential.getEncodedList());

            // Check the status of the specific bit
            return !getBit(decompressedBitstring, statusListIndex);
        } catch (Exception e) {
            log.error("Error validating credential status", e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR);
        }
    }

    /**
     * Generate a unique status list ID
     *
     * @param issuerId Issuer identifier
     * @return Generated status list ID
     */
    private String generateStatusListId(String issuerId) {
        return issuerId + "/credential/status/" + UUID.randomUUID().toString();
    }

    /**
     * Compress a bitstring using GZIP and encode with Base64
     *
     * @param bitstring Byte array to compress
     * @return Compressed and Base64 encoded string
     */
    private String compressBitstring(byte[] bitstring) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzipOS = new GZIPOutputStream(baos)) {
            gzipOS.write(bitstring);
            gzipOS.close();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
        }
    }

    /**
     * Decompress a Base64 encoded GZIP compressed bitstring
     *
     * @param encodedList Base64 encoded compressed bitstring
     * @return Decompressed byte array
     */
    private byte[] decompressBitstring(String encodedList) throws IOException {
        byte[] compressedBytes = Base64.getUrlDecoder().decode(encodedList);

        // Decompression logic would typically use GZIPInputStream
        // This is a simplified placeholder and would need a full implementation
        return compressedBytes;
    }

    /**
     * Update a specific bit in the bitstring
     *
     * @param bitstring Byte array representing the bitstring
     * @param index Index of the bit to update
     * @param status Status to set (0 or 1)
     */
    private void updateBit(byte[] bitstring, long index, int status) {
        if (index < 0 || index >= bitstring.length * 8) {
//            throw new CertifyException(ErrorConstants.INVALID_STATUS_LIST_INDEX);
            throw new CertifyException("INVALID_STATUS_LIST_INDEX");
        }

        int byteIndex = (int) (index / 8);
        int bitPosition = (int) (index % 8);

        if (status == 1) {
            bitstring[byteIndex] |= (1 << (7 - bitPosition)); // Set bit
        } else {
            bitstring[byteIndex] &= ~(1 << (7 - bitPosition)); // Clear bit
        }
    }

    /**
     * Get the status of a specific bit in the bitstring
     *
     * @param bitstring Byte array representing the bitstring
     * @param index Index of the bit to check
     * @return Status of the bit (true if set, false if unset)
     */
    private boolean getBit(byte[] bitstring, long index) {
        if (index < 0 || index >= bitstring.length * 8) {
//            throw new CertifyException(ErrorConstants.INVALID_STATUS_LIST_INDEX);
            throw new CertifyException("INVALID_STATUS_LIST_INDEX");

        }

        int byteIndex = (int) (index / 8);
        int bitPosition = (int) (index % 8);

        return ((bitstring[byteIndex] & (1 << (7 - bitPosition))) != 0);
    }
}