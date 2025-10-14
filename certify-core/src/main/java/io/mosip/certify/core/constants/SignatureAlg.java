package io.mosip.certify.core.constants;

/**
 * SignatureAlg is the constants file of supported VC sign algorithms.
 * TODO(later): convert this into a structure such that it enables
 *  consumers to choose VC sign algos with
 */
public class SignatureAlg {
    // LinkedDataSignature Algorithms
    public static final String RSA_SIGNATURE_SUITE_2018 = "RsaSignature2018";

    public static final String ED25519_SIGNATURE_SUITE_2018 = "Ed25519Signature2018";

    public static final String ED25519_SIGNATURE_SUITE_2020 = "Ed25519Signature2020";
    // EC K1 curves
    public static final String EC_K1_2016 = "EcdsaKoblitzSignature2016";
    public static final String EC_SECP256K1_2019 = "EcdsaSecp256k1Signature2019"; // secp256k1
    public static final String EC_SECP256R1_2019 = "EcdsaSecp256r1Signature2019";

    public static final String DATA_INTEGRITY = "DataIntegrityProof";
    // CryptoSuite names
    public static final String EC_RDFC_2019 = "ecdsa-rdfc-2019";
    public static final String EC_JCS_2019 = "ecdsa-jcs-2019";
    public static final String ED_RDFC_2022 = "eddsa-rdfc-2022";
    public static final String ED_JCS_2022 = "eddsa-jcs-2022";

    public static final String EC_SD_2023 = "ecdsa-sd-2023";// secp256r1
}
