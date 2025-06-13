package io.mosip.certify.utils;

import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

/**
 * Utility class to handle bit string operations for status lists
 * This utility provides static methods for manipulating encoded status lists
 */
@Slf4j
public final class BitStringStatusListUtils {

    // Private constructor to prevent instantiation
    private BitStringStatusListUtils() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Generate encoded list from a map of index-status pairs
     *
     * @param statusMap Map containing index -> status mappings
     * @param capacity Total capacity of the status list
     * @return Base64URL encoded compressed bitstring
     */
    public static String generateEncodedList(Map<Long, Boolean> statusMap, long capacity) {
        log.info("Generating encoded list from status map with {} entries for capacity {}",
                statusMap.size(), capacity);

        try {
            // Create bitstring array initialized to false (0)
            boolean[] bitstring = new boolean[(int) capacity];

            // Set the appropriate bits based on the status map
            for (Map.Entry<Long, Boolean> entry : statusMap.entrySet()) {
                long index = entry.getKey();
                boolean status = entry.getValue();

                if (index >= 0 && index < capacity) {
                    bitstring[(int) index] = status;
                } else {
                    log.warn("Index {} is out of bounds for capacity {}", index, capacity);
                }
            }

            // Convert bitstring to byte array
            byte[] byteArray = convertBitstringToByteArray(bitstring);

            // Compress the byte array
            byte[] compressedBytes = compressByteArray(byteArray);

            // Encode to base64url
            String encodedList = Base64.getUrlEncoder().withoutPadding().encodeToString(compressedBytes);

            log.info("Generated encoded list of length {} from {} status entries",
                    encodedList.length(), statusMap.size());

            return encodedList;

        } catch (Exception e) {
            log.error("Error generating encoded list from status map", e);
            throw new CertifyException("ENCODED_LIST_GENERATION_FAILED");
        }
    }

    /**
     * Creates an empty encoded list (all bits set to 0) according to W3C Bitstring Status List v1.0
     *
     * @param capacity the number of bits in the list
     * @return Multibase-encoded base64url (with no padding) string representing the GZIP-compressed bit array
     * @throws RuntimeException if compression fails
     */
    public static String createEmptyEncodedList(long capacity) {
        log.debug("Creating empty encoded list with capacity {}", capacity);

        // Ensure minimum size of 16KB (131,072 bits) as per specification
        long actualCapacity = Math.max(capacity, 131072L);

        int numBytes = (int) Math.ceil(actualCapacity / 8.0);
        byte[] emptyBitstring = new byte[numBytes];

        try {
            // GZIP compress the bitstring as required by the specification
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gzipOut = new GZIPOutputStream(baos)) {
                gzipOut.write(emptyBitstring);
            }
            byte[] compressedBitstring = baos.toByteArray();

            // Multibase-encode using base64url (with no padding) as required by specification
            String base64urlEncoded = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(compressedBitstring);

            return "u" + base64urlEncoded;

        } catch (IOException e) {
            throw new RuntimeException("Failed to compress bitstring", e);
        }
    }

    /**
     * Convert bitstring boolean array to byte array
     * Each byte contains 8 bits
     */
    private static byte[] convertBitstringToByteArray(boolean[] bitstring) {
        int byteLength = (bitstring.length + 7) / 8; // Round up to nearest byte
        byte[] byteArray = new byte[byteLength];

        for (int i = 0; i < bitstring.length; i++) {
            if (bitstring[i]) {
                int byteIndex = i / 8;
                int bitIndex = i % 8;
                byteArray[byteIndex] |= (1 << (7 - bitIndex)); // Set bit (MSB first)
            }
        }

        return byteArray;
    }

    /**
     * Compress byte array using GZIP compression
     */
    private static byte[] compressByteArray(byte[] input) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzipOut = new GZIPOutputStream(baos)) {

            gzipOut.write(input);
            gzipOut.finish();

            return baos.toByteArray();
        }
    }
}