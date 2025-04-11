package io.mosip.certify.utils;

import io.mosip.certify.entity.LedgerIssuanceTable;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.exception.BitstringStatusListException;
import io.mosip.certify.exception.RevocationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class BitStringUtils {
    private static final int DEFAULT_LIST_SIZE = 131_072; // 16 KB
    private static final int DEFAULT_STATUS_SIZE = 1;
    public static final int MINIMUM_BITSTRING_SIZE = 131072;

    /**
     * Set a specific bit in a byte array
     * @param bitstring The byte array containing the bitstring
     * @param index The index of the bit to set
     * @param value The value to set (0 or 1)
     */
    public static void setBitAtIndex(byte[] bitstring, long index, byte value) {
        int byteIndex = (int) (index / 8);
        int bitPosition = (int) (index % 8);

        if (byteIndex >= bitstring.length) {
            throw new IndexOutOfBoundsException("Index out of bounds for bitstring");
        }

        if (value == 1) {
            // Set the bit to 1
            bitstring[byteIndex] |= (1 << (7 - bitPosition));
        } else {
            // Set the bit to 0
            bitstring[byteIndex] &= ~(1 << (7 - bitPosition));
        }
    }

    /**
     * Check the value of a bit at a specific index
     * @param bitstring The byte array containing the bitstring
     * @param index The index of the bit to check
     * @return true if the bit is 1, false if the bit is 0
     */
    public static boolean checkBitAtIndex(byte[] bitstring, long index) {
        int byteIndex = (int) (index / 8);
        int bitPosition = (int) (index % 8);

        if (byteIndex >= bitstring.length) {
            throw new IndexOutOfBoundsException("Index out of bounds for bitstring");
        }

        return ((bitstring[byteIndex] & (1 << (7 - bitPosition))) != 0);
    }

    /**
     * Decompress GZIP compressed byte array
     */
    public static byte[] decompressGzip(byte[] compressedBytes) throws IOException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressedBytes);
             GZIPInputStream gzipIs = new GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzipIs.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        }
    }

    /**
     * Generate a compressed bitstring for a list of credentials
     * Implements Section 3.3 of the W3C Bitstring Status List specification
     *
     * @param issuedCredentials List of issued credentials
     * @param statusSize Size of each status entry in bits
     * @return Base64url encoded compressed bitstring
     * @throws BitstringStatusListException if generation fails
     */
    public static String generateBitstring(List<LedgerIssuanceTable> issuedCredentials, int statusSize) throws BitstringStatusListException {
        try {
            // Create a bitstring with minimum size (16KB)
            BitSet bitstring = new BitSet(MINIMUM_BITSTRING_SIZE);

            // Set bits for each credential based on its status
            for (LedgerIssuanceTable credential : issuedCredentials) {
                long statusListIndex = credential.getStatusListIndex();

                // If the credential is revoked/suspended (not valid), set the appropriate bit
                if (!"valid".equals(credential.getCredentialStatus())) {
                    long position = statusListIndex * statusSize;
                    if (position < 0 || position >= MINIMUM_BITSTRING_SIZE) {
                        throw new BitstringStatusListException("RANGE_ERROR",
                                "Status list index out of range: " + statusListIndex);
                    }
                    bitstring.set((int)position);
                }
            }

            // Compress the bitstring using GZIP
            return compressBitstring(bitstring, MINIMUM_BITSTRING_SIZE);
        } catch (IOException e) {
            throw new BitstringStatusListException("COMPRESSION_ERROR",
                    "Error compressing bitstring: " + e.getMessage());
        }
    }

    /**
     * Compress a bitstring using GZIP and encode it with Base64url
     *
     * @param bitstring The bitstring to compress
     * @param bitstringSize The size of the bitstring in bits
     * @return Base64url encoded compressed bitstring
     * @throws IOException if compression fails
     */
    private static String compressBitstring(BitSet bitstring, int bitstringSize) throws IOException {
        // Convert BitSet to byte array
        byte[] bitsetBytes = toByteArray(bitstring, bitstringSize);

        // Compress using GZIP
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(baos)) {
            gzipOutputStream.write(bitsetBytes);
        }

        // Base64url encode (with no padding)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
    }

    /**
     * Convert BitSet to byte array ensuring proper ordering
     *
     * @param bitset The BitSet to convert
     * @param bitstringSize The size of the bitstring in bits
     * @return Byte array representation of the bitstring
     */
    public static byte[] toByteArray(BitSet bitset, int bitstringSize) {
        // Calculate bytes needed (bitstringSize / 8, rounded up)
        int byteSize = (bitstringSize + 7) / 8;
        byte[] bytes = new byte[byteSize];

        // Convert BitSet to byte array with proper bit ordering
        for (int i = 0; i < bitstringSize; i++) {
            if (bitset.get(i)) {
                // Calculate byte index and bit position within byte
                int byteIndex = i / 8;
                int bitPosition = 7 - (i % 8); // MSB ordering within each byte
                bytes[byteIndex] |= (1 << bitPosition);
            }
        }

        return bytes;
    }

    /**
     * Expand a compressed bitstring
     * Implements Section 3.4 of the W3C Bitstring Status List specification
     *
     * @param compressedBitstring Base64url encoded compressed bitstring
     * @return Expanded BitSet
     * @throws BitstringStatusListException if expansion fails
     */
    public static BitSet expandCompressedList(String compressedBitstring) throws BitstringStatusListException {
        try {
            // Decode Base64url
            byte[] compressedBytes = Base64.getUrlDecoder().decode(compressedBitstring);

            // Decompress using GZIP
            ByteArrayInputStream bais = new ByteArrayInputStream(compressedBytes);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            try (GZIPInputStream gzipInputStream = new GZIPInputStream(bais)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = gzipInputStream.read(buffer)) != -1) {
                    baos.write(buffer, 0, len);
                }
            }

            byte[] expandedBytes = baos.toByteArray();

            // Convert to BitSet
            return fromByteArray(expandedBytes);
        } catch (IOException | IllegalArgumentException e) {
            throw new BitstringStatusListException("EXPANSION_ERROR",
                    "Error expanding bitstring: " + e.getMessage());
        }
    }

    /**
     * Convert byte array to BitSet ensuring proper ordering
     *
     * @param bytes The byte array to convert
     * @return BitSet representation
     */
    public static BitSet fromByteArray(byte[] bytes) {
        BitSet bitset = new BitSet(bytes.length * 8);

        // Convert byte array to BitSet with proper bit ordering
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                if ((bytes[i] & (1 << (7 - j))) != 0) {
                    bitset.set((i * 8) + j);
                }
            }
        }

        return bitset;
    }

    /**
     * Validate a credential status against a status list
     * Implements Section 3.2 of the W3C Bitstring Status List specification
     *
     * @param credential The credential to validate
     * @param statusListCredential The status list credential
     * @return A map containing validation results
     * @throws BitstringStatusListException if validation fails
     */
    public static Map<String, Object> validateCredential(
            LedgerIssuanceTable credential,
            StatusListCredential statusListCredential) throws BitstringStatusListException {

        if (!credential.getStatusPurpose().equals(statusListCredential.getStatusPurpose())) {
            throw new BitstringStatusListException("STATUS_VERIFICATION_ERROR",
                    "Status purpose mismatch between credential and status list");
        }

        String compressedBitstring = statusListCredential.getEncodedList();

        BitSet expandedBitstring = expandCompressedList(compressedBitstring);

        int statusSize = statusListCredential.getStatusSize() != null ? statusListCredential.getStatusSize() : 1;
        if (expandedBitstring.size() / statusSize < MINIMUM_BITSTRING_SIZE) {
            throw new BitstringStatusListException("STATUS_LIST_LENGTH_ERROR",
                    "Status list length does not meet minimum length requirement");
        }

        long credentialIndex = credential.getStatusListIndex();
        int position = (int)(credentialIndex * statusSize);

        if (position < 0 || position >= expandedBitstring.size()) {
            throw new BitstringStatusListException("RANGE_ERROR",
                    "Status list index out of range: " + credentialIndex);
        }

        boolean isSet = expandedBitstring.get(position);

        Map<String, Object> result = new HashMap<>();
        result.put("status", isSet ? 1 : 0);
        result.put("purpose", credential.getStatusPurpose());

        if ("revocation".equals(credential.getStatusPurpose()) ||
                "suspension".equals(credential.getStatusPurpose())) {
            result.put("valid", !isSet);
        } else if ("refresh".equals(credential.getStatusPurpose())) {
            result.put("refreshAvailable", isSet);
        } else if ("message".equals(credential.getStatusPurpose())) {
            if (credential.getStatusMessage() != null) {
                result.put("message", "Status message at index " + position);
            }
        }

        return result;
    }

    /**
     * Generate a complete BitstringStatusListCredential
     * Implements Section 3.1 of the W3C Bitstring Status List specification
     *
     * @param issuedCredentials List of issued credentials
     * @param issuer The issuer ID
     * @param statusPurpose The status purpose
     * @param statusSize Status size in bits
     * @return A complete StatusListCredential entity
     * @throws BitstringStatusListException if generation fails
     */
    public static StatusListCredential generateStatusListCredential(
            List<LedgerIssuanceTable> issuedCredentials,
            String issuer,
            String statusPurpose,
            String domainUrl,
            int statusSize) throws BitstringStatusListException {


        String encodedList = generateBitstring(issuedCredentials, statusSize);
        String statusListId = domainUrl + "/credential/status/" + UUID.randomUUID().toString();
        // Create and return the status list credential
        StatusListCredential statusListCredential = new StatusListCredential();
        statusListCredential.setId(statusListId);
        statusListCredential.setIssuerId(issuer);
        statusListCredential.setType("BitstringStatusListCredential");
        statusListCredential.setEncodedList(encodedList);
        statusListCredential.setListSize(MINIMUM_BITSTRING_SIZE);
        statusListCredential.setStatusPurpose(statusPurpose);
        statusListCredential.setStatusSize(statusSize);
        statusListCredential.setValidFrom(java.time.LocalDateTime.now());

        return statusListCredential;
    }


}

