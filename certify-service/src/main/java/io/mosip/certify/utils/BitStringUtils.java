package io.mosip.certify.utils;

import io.mosip.certify.entity.LedgerIssuanceTable;
import io.mosip.certify.entity.StatusListCredential;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class BitStringUtils {
    private static final int DEFAULT_LIST_SIZE = 131_072; // 16 KB
    private static final int DEFAULT_STATUS_SIZE = 1;
    /**
     * Set a specific bit in a byte array
     */
    public static void setBitAtIndex(byte[] bitstring, long index, byte value) {
        int byteIndex = (int) (index / 8);
        int bitPosition = (int) (index % 8);

        if (value == 1) {
            bitstring[byteIndex] |= (1 << (7 - bitPosition));
        } else {
            bitstring[byteIndex] &= ~(1 << (7 - bitPosition));
        }
    }

    /**
     * Check the value of a bit at a specific index
     */
    public static boolean checkBitAtIndex(byte[] bitstring, long index) {
        int byteIndex = (int) (index / 8);
        int bitPosition = (int) (index % 8);

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
     * Compress bitstring using GZIP and Base64 encode
     */
    private String compressAndEncodeList(byte[] bitstring) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzipOs = new GZIPOutputStream(baos)) {
            gzipOs.write(bitstring);
            gzipOs.close();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
        }
    }

    /**
     * Expand compressed and encoded list
     */
    public byte[] expandCompressedList(String compressedEncodedList) throws Exception {
        try {
            byte[] compressedBytes = Base64.getUrlDecoder().decode(compressedEncodedList);
            return BitStringUtils.decompressGzip(compressedBytes);
        } catch (Exception e) {
            throw new Exception("Error expanding compressed list", e);
        }
    }

    /**
     * Generate bitstring from issued credentials
     */
    public byte[] generateBitstring(List<LedgerIssuanceTable> issuedCredentials) {
        byte[] bitstring = new byte[DEFAULT_LIST_SIZE / 8]; // Convert bits to bytes

        for (LedgerIssuanceTable entry : issuedCredentials) {
            BitStringUtils.setBitAtIndex(
                    bitstring,
                    entry.getStatusListIndex(),
                    entry.getCredentialStatus().equals("revoked") ? (byte)1 : (byte)0
            );
        }

        return bitstring;
    }
}