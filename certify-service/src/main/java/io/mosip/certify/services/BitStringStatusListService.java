package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.BitStringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;
/**
 * Service to handle bit string operations for status lists
 * This service is responsible for manipulating the encoded status list
 */
@Slf4j
@Service
public class BitStringStatusListService {

    /**
     * Creates an empty encoded list (all bits set to 0) according to W3C Bitstring Status List v1.0
     *
     * @param capacity the number of bits in the list
     * @return Multibase-encoded base64url (with no padding) string representing the GZIP-compressed bit array
     * @throws RuntimeException if compression fails
     */
    public String createEmptyEncodedList(long capacity) {
        log.debug("Creating empty encoded list with capacity {}", capacity);

        // Ensure minimum size of 16KB (131,072 bits) as per specification
        long actualCapacity = Math.max(capacity, 131072L);

        // Calculate number of bytes needed
        int numBytes = (int) Math.ceil(actualCapacity / 8.0);
        byte[] emptyBitstring = new byte[numBytes];

        // All bytes initialized to 0 by default in Java (which is what we want)

        try {
            // GZIP compress the bitstring as required by the specification
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gzipOut = new GZIPOutputStream(baos)) {
                gzipOut.write(emptyBitstring);
            }
            byte[] compressedBitstring = baos.toByteArray();

            // Multibase-encode using base64url (with no padding) as required by specification
            // Note: The 'u' prefix indicates base64url encoding in Multibase
            String base64urlEncoded = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(compressedBitstring);

            return "u" + base64urlEncoded;

        } catch (IOException e) {
            throw new RuntimeException("Failed to compress bitstring", e);
        }
    }

}