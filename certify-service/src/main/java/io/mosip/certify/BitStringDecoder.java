package io.mosip.certify;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

public class BitStringDecoder {

    public static void main(String[] args) throws IOException {
        boolean[] decoded = decodeEncodedList("uH4sIAAAAAAAA_-3OIQEAAAgDMCSS_mlpARdbglUBAAAAkGS-AwAAAAAAAAAAAECQ_g4AcGgB3HGHQQBAAAA", 262144);
        System.out.println("Decoded length: " + decoded.length);
        System.out.println("decoded : "+ decoded[118868]);

    }

    /**
     * Decodes an encoded list string (Base64URL + GZIP) back to a boolean array bitstring.
     *
     * @param encodedList The encoded list string (may have multibase prefix 'u').
     * @param capacity The number of bits to decode (should match the original capacity).
     * @return boolean array representing the bitstring status list.
     */
    public static boolean[] decodeEncodedList(String encodedList, int capacity) throws IOException {
        if (encodedList == null || encodedList.isEmpty()) {
            throw new IllegalArgumentException("Encoded list string is null or empty");
        }
            String base64Part = encodedList.startsWith("u") ? encodedList.substring(1) : encodedList;
            byte[] compressedBytes = Base64.getUrlDecoder().decode(base64Part);
            byte[] decompressedBytes = decompress(compressedBytes);
            boolean[] bitstring = new boolean[capacity];
            for (int i = 0; i < capacity; i++) {
                int byteIndex = i / 8;
                int bitIndex = i % 8;
                if (byteIndex < decompressedBytes.length) {
                    bitstring[i] = ((decompressedBytes[byteIndex] >> (7 - bitIndex)) & 1) == 1;
                } else {
                    bitstring[i] = false;
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
