package io.mosip.certify.utils;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

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
                case SignatureAlg.ED25519_SIGNATURE_SUITE_2018:
                    verificationMethod = generateEd25519VerificationMethod(publicKey, issuerURI, issuerPublicKeyURI);
                    break;
                case SignatureAlg.ED25519_SIGNATURE_SUITE_2020:
                    verificationMethod = generateEd25519VerificationMethod(publicKey, issuerURI, issuerPublicKeyURI);
                    break;
                case SignatureAlg.RSA_SIGNATURE_SUITE_2018:
                    verificationMethod = generateRSAVerificationMethod(publicKey, issuerURI, issuerPublicKeyURI);
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
    
}
