package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.BitStringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Base64;

/**
 * Service to handle bit string operations for status lists
 * This service is responsible for manipulating the encoded status list
 */
@Slf4j
@Service
public class BitStringStatusListService {

    /**
     * Creates an empty encoded list (all bits set to 0)
     *
     * @param capacity the number of bits in the list
     * @return Base64-encoded string representing the bit array
     */
    public String createEmptyEncodedList(long capacity) {
        log.debug("Creating empty encoded list with capacity {}", capacity);

        // Calculate number of bytes needed
        int numBytes = (int) Math.ceil(capacity / 8.0);
        byte[] emptyList = new byte[numBytes];

        // All bytes initialized to 0 by default in Java
        return Base64.getEncoder().encodeToString(emptyList);
    }

    /**
     * Find the next available index (bit set to 0) in the encoded list
     *
     * @param encodedList Base64-encoded string representing the bit array
     * @return next available index, or -1 if no available index found
     */
    public long findNextAvailableIndex(String encodedList) {
        log.debug("Finding next available index in encoded list");

        try {
            byte[] decodedList = Base64.getDecoder().decode(encodedList);

            // Find first bit that is 0
            for (int byteIndex = 0; byteIndex < decodedList.length; byteIndex++) {
                byte currentByte = decodedList[byteIndex];

                // Skip if byte is full (all bits set to 1)
                if (currentByte == (byte) 0xFF) {
                    continue;
                }

                // Check each bit in the byte
                for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
                    // Calculate mask for current bit
                    byte mask = (byte) (1 << bitIndex);

                    // If bit is 0, we found an available index
                    if ((currentByte & mask) == 0) {
                        return (byteIndex * 8) + bitIndex;
                    }
                }
            }

            // No available index found
            return -1;

        } catch (IllegalArgumentException e) {
            log.error("Invalid Base64 encoded list", e);
            throw new CertifyException("INVALID_ENCODED_LIST");
        }
    }

    /**
     * Update the status bit at the specified index
     *
     * @param encodedList Base64-encoded string representing the bit array
     * @param index the index to update
     * @param setValue true to set bit to 1, false to set to 0
     * @return updated Base64-encoded string
     */
    public String updateStatusAtIndex(String encodedList, long index, boolean setValue) {
        log.debug("Updating status at index {} to {}", index, setValue);

        try {
            byte[] decodedList = Base64.getDecoder().decode(encodedList);

            int byteIndex = (int) (index / 8);
            int bitIndex = (int) (index % 8);

            if (byteIndex >= decodedList.length) {
                log.error("Index out of bounds: {} (max bytes: {})", byteIndex, decodedList.length);
                throw new CertifyException("INDEX_OUT_OF_BOUNDS");
            }

            byte mask = (byte) (1 << bitIndex);

            if (setValue) {
                // Set bit to 1
                decodedList[byteIndex] |= mask;
            } else {
                // Set bit to 0
                decodedList[byteIndex] &= ~mask;
            }

            return Base64.getEncoder().encodeToString(decodedList);

        } catch (IllegalArgumentException e) {
            log.error("Invalid Base64 encoded list", e);
            throw new CertifyException("INVALID_ENCODED_LIST");
        }
    }

    /**
     * Check if a bit is set at the specified index
     *
     * @param encodedList Base64-encoded string representing the bit array
     * @param index the index to check
     * @return true if bit is 1, false if bit is 0
     */
    public boolean isStatusSetAtIndex(String encodedList, long index) {
        log.debug("Checking status at index {}", index);

        try {
            byte[] decodedList = Base64.getDecoder().decode(encodedList);

            int byteIndex = (int) (index / 8);
            int bitIndex = (int) (index % 8);

            if (byteIndex >= decodedList.length) {
                log.error("Index out of bounds: {} (max bytes: {})", byteIndex, decodedList.length);
                throw new CertifyException("INDEX_OUT_OF_BOUNDS");
            }

            byte mask = (byte) (1 << bitIndex);

            // Return true if bit is 1, false if bit is 0
            return (decodedList[byteIndex] & mask) != 0;

        } catch (IllegalArgumentException e) {
            log.error("Invalid Base64 encoded list", e);
            throw new CertifyException("INVALID_ENCODED_LIST");
        }
    }
}