package io.mosip.certify.utils;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.BitSet;
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
     * @param capacityInKB Total capacity of the status list.
     * @return Base64URL encoded compressed bitstring.
     */
    public static String updateEncodedList(String encodedStatusList, Map<Long, Boolean> statusMap, long capacityInKB) {
        log.info("Generating encoded list from status map with {} entries for capacity {}",
                statusMap.size(), capacityInKB);

        try {
            long actualCapacity = Math.max(capacityInKB * 1024L * 8L, 131072L);
            if (actualCapacity > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("Capacity exceeds maximum supported size for Java BitSet");
            }
            BitSet bitstring = decodeEncodedList(encodedStatusList, (int) actualCapacity);
            for (Map.Entry<Long, Boolean> entry : statusMap.entrySet()) {
                long index = entry.getKey();
                boolean status = entry.getValue();

                if (index >= 0 && index < actualCapacity) {
                    bitstring.set((int) index, status);
                } else {
                    log.warn("Index {} is out of bounds for capacity {}", index, actualCapacity);
                }
            }
            byte[] byteArray = convertBitstringToByteArray(bitstring, (int) actualCapacity);
            String encodedList = compressAndEncode(byteArray);

            log.info("Generated encoded list of length {} from {} status entries", encodedList.length(), statusMap.size());

            return encodedList;
        } catch (Exception e) {
            log.error("Error generating encoded list from status map", e);
            throw new CertifyException(ErrorConstants.ENCODED_LIST_UPDATE_FAILED);
        }
    }

    /**
     * Creates an empty encoded list (all bits set to 0) according to W3C Bitstring Status List v1.0.
     *
     * @param capacityInKB Capacity of the status list in kilobytes (KB).
     * @return Multibase-encoded base64url string representing the GZIP-compressed bit array.
     */
    public static String createEmptyEncodedList(long capacityInKB) {
        log.debug("Creating empty encoded list with capacity {}", capacityInKB);
        long actualCapacity = Math.max(capacityInKB * 1024L * 8L, 131072L);
        if (actualCapacity > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Capacity exceeds maximum supported size for Java BitSet");
        }
        int numBytes = (int) Math.ceil(actualCapacity / 8.0);
        BitSet emptyBitstring = new BitSet((int) actualCapacity);
        byte[] emptyByteArray = convertBitstringToByteArray(emptyBitstring, (int) actualCapacity);
        return "u" + compressAndEncode(emptyByteArray);
    }

    /**
     * Convert bitstring boolean array to byte array. Each byte contains 8 bits.
     */
    private static byte[] convertBitstringToByteArray(BitSet bitstring, int capacity) {
        int byteLength = (capacity + 7) / 8;
        byte[] byteArray = new byte[byteLength];
        for (int i = 0; i < capacity; i++) {
            if (bitstring.get(i)) {
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

    /**
     * Decodes an encoded list string (Base64URL + GZIP) back to a boolean array bitstring.
     *
     * @param encodedList The encoded list string (may have multibase prefix 'u').
     * @param capacity The number of bits to decode (should match the original capacity).
     * @return boolean array representing the bitstring status list.
     */
    private static BitSet decodeEncodedList(String encodedList, int capacity) throws IOException {
        if (encodedList == null || encodedList.isEmpty()) {
            throw new IllegalArgumentException("Encoded list string is null or empty");
        }
        String base64Part = encodedList.startsWith("u") ? encodedList.substring(1) : encodedList;
        byte[] compressedBytes = Base64.getUrlDecoder().decode(base64Part);
        byte[] decompressedBytes = decompress(compressedBytes);
        BitSet bitstring = new BitSet(capacity);
        for (int i = 0; i < capacity; i++) {
            int byteIndex = i / 8;
            int bitIndex = i % 8;
            if (byteIndex < decompressedBytes.length) {
                boolean bit = ((decompressedBytes[byteIndex] >> (7 - bitIndex)) & 1) == 1;
                bitstring.set(i, bit);
            } else {
                bitstring.set(i, false);
            }
        }
        return bitstring;
    }

    /**
     * GZIP decompress a byte array.
     */
    private static byte[] decompress(byte[] compressedBytes) throws IOException {
        try (java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(compressedBytes);
             java.util.zip.GZIPInputStream gzipIn = new java.util.zip.GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzipIn.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        }
    }
}