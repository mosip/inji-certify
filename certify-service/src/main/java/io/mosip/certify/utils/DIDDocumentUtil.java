package io.mosip.certify.utils;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nimbusds.jose.jwk.RSAKey;

import io.ipfs.multibase.Multibase;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DIDDocumentUtil {

    private static final String MULTICODEC_PREFIX = "ed01";

    public static Map<String, Object> generateDIDDocument(String vcSignAlgorithm, String certificateString, String issuerURI, String issuerPublicKeyURI) {

        HashMap<String,Object> didDocument = new HashMap<String,Object>();
        didDocument.put("@context", Collections.singletonList("https://www.w3.org/ns/did/v1"));
        didDocument.put("alsoKnownAs", new ArrayList<>());
        didDocument.put("service", new ArrayList<>());
        didDocument.put("id", issuerURI);
        didDocument.put("authentication", Collections.singletonList(issuerPublicKeyURI));
        didDocument.put("assertionMethod", Collections.singletonList(issuerPublicKeyURI));

        Map<String, Object> verificationMethod = null;
        PublicKey publicKey = loadPublicKeyFromCertificate(certificateString);
        try {
            switch (vcSignAlgorithm) {
                case SignatureAlg.EC_SECP256K1_2019:
                    verificationMethod = generateECK12019VerificationMethod(publicKey, issuerURI, issuerPublicKeyURI);
                    break;
                case SignatureAlg.ED25519_SIGNATURE_SUITE_2018:
                    verificationMethod = generateEd25519VerificationMethod(publicKey, issuerURI, issuerPublicKeyURI);
                    break;
                case SignatureAlg.ED25519_SIGNATURE_SUITE_2020:
                    verificationMethod = generateEd25519VerificationMethod(publicKey, issuerURI, issuerPublicKeyURI);
                    break;
                case SignatureAlg.RSA_SIGNATURE_SUITE_2018:
                    verificationMethod = generateRSAVerificationMethod(publicKey, issuerURI, issuerPublicKeyURI);
                    break;
                case SignatureAlg.EC_SECP256R1_2019:
                    verificationMethod = generateECR1VerificationMethod(publicKey, issuerURI, issuerPublicKeyURI);
                    break;
                default:
                    log.error("Unsupported signature algorithm provided :" + vcSignAlgorithm);
                    throw new CertifyException(ErrorConstants.UNSUPPORTED_ALGORITHM);
            }
        } catch(CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Exception occured while generating verification method for given certificate", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.VERIFICATION_METHOD_GENERATION_FAILED);
        }

        didDocument.put("verificationMethod", Collections.singletonList(verificationMethod));
        return didDocument;
    }

    private static Map<String, Object> generateECR1VerificationMethod(PublicKey publicKey, String issuerURI, String issuerPublicKeyURI) {
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        BigInteger yBI = ecPublicKey.getW().getAffineY();
        byte prefixByte = yBI.testBit(0) ? (byte) 0x03 : (byte) 0x02;
        // Compressed format: 0x02 or 0x03 || X
        byte[] compressed = ByteBuffer.allocate(1 + 32)
                .put(prefixByte)
                .put(ecPublicKey.getW().getAffineX().toByteArray())
                .array();

        // P-256 compressed public key multicodec prefix: 0x1201(varint form of 0x8024)
        byte[] prefix = HexFormat.of().parseHex("8024");
        byte[] finalBytes = new byte[prefix.length + compressed.length];
        System.arraycopy(prefix, 0, finalBytes, 0, prefix.length);
        System.arraycopy(compressed, 0, finalBytes, prefix.length, compressed.length);
        String publicKeyMultibase = Multibase.encode(Multibase.Base.Base58BTC, finalBytes);

        Map<String, Object> verificationMethod = new HashMap<>();
        verificationMethod.put("id", issuerPublicKeyURI);
        verificationMethod.put("type", "EcdsaSecp256r1VerificationKey2019");
        verificationMethod.put("@context", "https://w3id.org/security/suites/ecdsa-2019/v1");
        verificationMethod.put("controller", issuerURI);
        verificationMethod.put("publicKeyMultibase", publicKeyMultibase);
        return verificationMethod;
    }

    private static PublicKey loadPublicKeyFromCertificate(String certificateString) {
        try {
            ByteArrayInputStream fis = new ByteArrayInputStream(certificateString.getBytes());
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);
            return certificate.getPublicKey();
        } catch (Exception e) {
            log.error("Convertion from certificate to public key failed", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.INVALID_CERTIFICATE);
        }
    }

     private static Map<String, Object> generateEd25519VerificationMethod(PublicKey publicKey, String issuerURI, String issuerPublicKeyURI) throws Exception {

        BCEdDSAPublicKey edKey = (BCEdDSAPublicKey) publicKey;
        byte[] rawBytes = edKey.getPointEncoding();
        byte[] multicodecBytes = HexFormat.of().parseHex(MULTICODEC_PREFIX);
        byte[] finalBytes = new byte[multicodecBytes.length + rawBytes.length];
        System.arraycopy(multicodecBytes, 0, finalBytes, 0, multicodecBytes.length);
        System.arraycopy(rawBytes, 0, finalBytes, multicodecBytes.length, rawBytes.length);
        String publicKeyMultibase = Multibase.encode(Multibase.Base.Base58BTC, finalBytes);
        
        Map<String, Object> verificationMethod = new HashMap<>();
        verificationMethod.put("id", issuerPublicKeyURI);
        verificationMethod.put("type", "Ed25519VerificationKey2020");
        verificationMethod.put("@context", "https://w3id.org/security/suites/ed25519-2020/v1");
        verificationMethod.put("controller", issuerURI);
        verificationMethod.put("publicKeyMultibase", publicKeyMultibase);
        return verificationMethod;
    }

    private static Map<String, Object> generateRSAVerificationMethod(PublicKey publicKey, String issuerURI, String issuerPublicKeyURI) throws Exception {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey).build();
        Map<String,Object> publicKeyJwk = rsaKey.toJSONObject();

        Map<String, Object> verificationMethod = new HashMap<>();
        verificationMethod.put("id", issuerPublicKeyURI);
        verificationMethod.put("type", "JsonWebKey2020");
        verificationMethod.put("@context", "https://w3id.org/security/suites/jws-2020/v1");
        verificationMethod.put("controller", issuerURI);
        verificationMethod.put("publicKeyJwk", publicKeyJwk);
        return verificationMethod;
    }

    private static Map<String, Object> generateECK12019VerificationMethod(PublicKey publicKey, String issuerURI, String issuerPublicKeyURI) {
        // TODO: can validate the key or directly assume the curve here and
        //  go ahead or use P_256 only if `nimbusCurve` is having same value.
        ECKey nimbusKey = new ECKey.Builder(Curve.SECP256K1, (ECPublicKey) publicKey)
                .build();

        Map<String, Object> verificationMethod = new HashMap<>();
        verificationMethod.put("id", issuerPublicKeyURI);

        // ref: https://github.com/w3c-ccg/lds-ecdsa-secp256k1-2019/issues/8
        verificationMethod.put("type", "EcdsaSecp256k1VerificationKey2019");
        verificationMethod.put("@context", "https://w3id.org/security/v1");
        // (improvement): can also add expires key here
        verificationMethod.put("controller", issuerURI);
        verificationMethod.put("publicKeyJwk", nimbusKey.toJSONObject());
        // NOTE: Advice against using publicKeyHex by the spec author
        // ref: https://github.com/w3c-ccg/lds-ecdsa-secp256k1-2019/issues/4
        // ref: https://w3c.github.io/vc-data-integrity/vocab/security/vocabulary.html#publicKeyHex

        // As per the below spec, publicKeyBase58 is also supported
        // ref: https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1signature2019
        return verificationMethod;
    }
}
