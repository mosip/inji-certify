package io.mosip.certify.core.constants;

/**
 * SignatureAlg is the constants file of supported VC sign algorithms.
 * TODO(later): convert this into a structure such that it enables
 *  consumers to choose VC sign algos with
 */
public class SignatureAlg {
    // LinkedDataSignature Algorithms
    public static final String RSA_SIGNATURE_SUITE = "RsaSignature2018";

    public static final String ED25519_SIGNATURE_SUITE = "Ed25519Signature2018";

    public static final String ED25519_SIGNATURE_SUITE_2020 = "Ed25519Signature2020";

    // RS256, PS256, ES256 --> JWSAlgorithm.RS256.getName();
}
