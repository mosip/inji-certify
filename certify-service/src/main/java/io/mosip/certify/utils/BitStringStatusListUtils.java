package io.mosip.certify.utils;

import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

/**
 * Utility class to handle bit string operations for status lists.
 * This utility provides static methods for manipulating encoded status lists.
 */
@Slf4j
public final class BitStringStatusListUtils {

    // Private constructor to prevent instantiation
    private BitStringStatusListUtils() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Generate an encoded list from a map of index-status pairs.
     *
     * @param statusMap Map containing index -> status mappings.
     * @param capacity Total capacity of the status list.
     * @return Base64URL encoded compressed bitstring.
     */
    public static String generateEncodedList(Map<Long, Boolean> statusMap, long capacity) {
        log.info("Generating encoded list from status map with {} entries for capacity {}",
                statusMap.size(), capacity);

        try {
            boolean[] bitstring = new boolean[(int) capacity];
            for (Map.Entry<Long, Boolean> entry : statusMap.entrySet()) {
                long index = entry.getKey();
                boolean status = entry.getValue();

                if (index >= 0 && index < capacity) {
                    bitstring[(int) index] = status;
                } else {
                    log.warn("Index {} is out of bounds for capacity {}", index, capacity);
                }
            }
            byte[] byteArray = convertBitstringToByteArray(bitstring);
            String encodedList = compressAndEncode(byteArray);

            log.info("Generated encoded list of length {} from {} status entries", encodedList.length(), statusMap.size());

            return encodedList;
        } catch (Exception e) {
            log.error("Error generating encoded list from status map", e);
            throw new CertifyException("ENCODED_LIST_GENERATION_FAILED");
        }
    }

    /**
     * Creates an empty encoded list (all bits set to 0) according to W3C Bitstring Status List v1.0.
     *
     * @param capacity The number of bits in the list.
     * @return Multibase-encoded base64url string representing the GZIP-compressed bit array.
     */
    public static String createEmptyEncodedList(long capacity) {
        log.debug("Creating empty encoded list with capacity {}", capacity);
        long actualCapacity = Math.max(capacity, 131072L);
        int numBytes = (int) Math.ceil(actualCapacity / 8.0);
        byte[] emptyBitstring = new byte[numBytes];
        return "u" + compressAndEncode(emptyBitstring);
    }

    /**
     * Convert bitstring boolean array to byte array. Each byte contains 8 bits.
     */
    private static byte[] convertBitstringToByteArray(boolean[] bitstring) {
        int byteLength = (bitstring.length + 7) / 8;
        byte[] byteArray = new byte[byteLength];
        for (int i = 0; i < bitstring.length; i++) {
            if (bitstring[i]) {
                int byteIndex = i / 8;
                int bitIndex = i % 8;
                byteArray[byteIndex] |= (1 << (7 - bitIndex));
            }
        }
        return byteArray;
    }

    /**
     * Compresses a byte array using GZIP and then encodes it to Base64URL.
     * This method centralizes the duplicated logic.
     *
     * @param input The byte array to compress and encode.
     * @return A Base64URL encoded string.
     * @throws RuntimeException if compression or encoding fails.
     */
    private static String compressAndEncode(byte[] input) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzipOut = new GZIPOutputStream(baos)) {

            gzipOut.write(input);
            gzipOut.finish();
            byte[] compressedBytes = baos.toByteArray();

            return Base64.getUrlEncoder().withoutPadding().encodeToString(compressedBytes);
        } catch (IOException e) {
            log.error("Failed to compress and encode bitstring", e);
            throw new RuntimeException("Failed to compress and encode bitstring", e);
        }
    }
}