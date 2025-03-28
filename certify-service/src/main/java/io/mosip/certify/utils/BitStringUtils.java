//package io.mosip.certify.utils;
//
//import java.nio.ByteBuffer;
//import java.util.BitSet;
//import java.util.Base64;
//import java.util.zip.Deflater;
//import java.util.zip.Inflater;
//
//public class BitStringStatusListUtil {
//
//    /**
//     * Creates a new empty bitstring of the specified size
//     */
//    public static String createEmptyBitstring(int size) {
//        BitSet bitSet = new BitSet(size);
//        return encodeBitstring(bitSet, size);
//    }
//
//    /**
//     * Updates a bit in the encoded bitstring
//     */
//    public static String updateBitstring(String encodedBitstring, int index, boolean value) {
//        BitSet bitSet = decodeBitstring(encodedBitstring);
//        bitSet.set(index, value);
//        return encodeBitstring(bitSet, bitSet.length());
//    }
//
//    /**
//     * Gets the value of a bit in the encoded bitstring
//     */
//    public static boolean getBitstringValue(String encodedBitstring, int index) {
//        BitSet bitSet = decodeBitstring(encodedBitstring);
//        return bitSet.get(index);
//    }
//
//    /**
//     * Encodes a BitSet as a compressed Base64 string
//     */
//    private static String encodeBitstring(BitSet bitSet, int size) {
//        byte[] bytes = bitSet.toByteArray();
//
//        // Compress the bytes
//        byte[] compressedBytes = compress(bytes);
//
//        // Convert to Base64
//        return Base64.getEncoder().encodeToString(compressedBytes);
//    }
//
//    /**
//     * Decodes a compressed Base64 string into a BitSet
//     */
//    private static BitSet decodeBitstring(String encodedBitstring) {
//        byte[] compressedBytes = Base64.getDecoder().decode(encodedBitstring);
//
//        // Decompress the bytes
//        byte[] decompressedBytes = decompress(compressedBytes);
//
//        return BitSet.valueOf(decompressedBytes);
//    }
//
//    /**
//     * Compresses a byte array
//     */
//    private static byte[] compress(byte[] data) {
//        Deflater deflater = new Deflater();
//        deflater.setInput(data);
//        deflater.finish();
//
//        byte[] buffer = new byte[data.length];
//        int compressedSize = deflater.deflate(buffer);
//
//        byte[] compressedData = new byte[compressedSize];
//        System.arraycopy(buffer, 0, compressedData, 0, compressedSize);
//
//        deflater.end();
//        return compressedData;
//    }
//
//    /**
//     * Decompresses a byte array
//     */
//    private static byte[] decompress(byte[] compressedData) {
//        Inflater inflater = new Inflater();
//        inflater.setInput(compressedData);
//
//        byte[] buffer = new byte[1024];
//        int resultSize = 0;
//        ByteBuffer result = ByteBuffer.allocate(1024);
//
//        try {
//            while (!inflater.finished()) {
//                int count = inflater.inflate(buffer);
//                result.put(buffer, 0, count);
//                resultSize += count;
//            }
//        } catch (Exception e) {
//            throw new RuntimeException("Failed to decompress data", e);
//        } finally {
//            inflater.end();
//        }
//
//        byte[] decompressedData = new byte[resultSize];
//        result.flip();
//        result.get(decompressedData, 0, resultSize);
//
//        return decompressedData;
//    }
//}