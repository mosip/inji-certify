package io.mosip.certify.services;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.ipfs.multibase.Multibase;

public class SVGRenderUtils {
    /**
     * Generate SVG digest for @param svg image as per spec.
     * ref: https://w3c-ccg.github.io/vc-render-method/#svgrenderingtemplate
     *
     * @param svg
     * @return
     */
    public static String getDigestMultibase(String svg) {
        /*
        digestMultibase:	An optional multibase-encoded multihash of the SVG image.
                            The multibase value MUST be z and the multihash value MUST
                             be SHA-2 with 256-bits of output (0x12).
         */
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] sha256 = digest.digest(svg.getBytes(StandardCharsets.UTF_8));
            return Multibase.encode(Multibase.Base.Base58BTC, sha256);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
