package io.mosip.certify.utils;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.services.CertifyIssuanceServiceImpl;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.CertificateDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nimbusds.jose.jwk.RSAKey;

import io.ipfs.multibase.Multibase;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.BigIntegers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class DIDDocumentUtil {
    @Autowired
    KeymanagerService keymanagerService;

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Value("#{${mosip.certify.credential-config.credential-signing-alg-values-supported}}")
    private LinkedHashMap<String, List<String>> credentialSigningAlgValuesSupportedMap;

    private static final String MULTICODEC_PREFIX = "ed01";

    public Map<String, Object> generateDIDDocument(String didUrl) {
        HashMap<String, Object> didDocument = new HashMap<>();
        didDocument.put("@context", Collections.singletonList("https://www.w3.org/ns/did/v1"));
        didDocument.put("alsoKnownAs", new ArrayList<>());
        didDocument.put("service", new ArrayList<>());
        didDocument.put("id", didUrl);
        didDocument.put("authentication", Collections.singletonList(didUrl));
        didDocument.put("assertionMethod", Collections.singletonList(didUrl));

        // Fetch the credentialConfig map
        Map<String, List<String>> credentialConfigMap = getSignatureCryptoSuiteMap();

        // Use a Set to track unique verification methods by their "id"
        Set<String> uniqueIds = new HashSet<>();
        List<Map<String, Object>> verificationMethods = credentialConfigMap.entrySet().stream()
                .flatMap(entry -> {
                    List<String> keyParams = entry.getValue();
                    String appId = keyParams.get(0);
                    String refId = keyParams.get(1);
                    AllCertificatesDataResponseDto kidResponse = keymanagerService.getAllCertificates(appId, refId != null ? Optional.of(refId) : Optional.empty());

                    if (kidResponse == null || kidResponse.getAllCertificates() == null) {
                        log.error("No certificates found for appId: {} and refId: {}", keyParams.get(0), keyParams.get(1));
                        throw new CertifyException("No certificates found");
                    }

                    return Arrays.stream(kidResponse.getAllCertificates())
                            .map(certificateData -> {
                                String certificateString = certificateData.getCertificateData();
                                String kid = certificateData.getKeyId();
                                Map<String, Object> verificationMethod = generateVerificationMethod(keyParams.get(2), certificateString, didUrl, kid);

                                // Add only if the "id" is unique
                                String verificationId = (String) verificationMethod.get("id");
                                if (uniqueIds.add(verificationId)) {
                                    return verificationMethod;
                                }
                                return null; // Skip duplicates
                            })
                            .filter(Objects::nonNull); // Remove null entries
                })
                .collect(Collectors.toList());

        didDocument.put("verificationMethod", verificationMethods);

        return didDocument;
    }

    private static Map<String, Object> generateVerificationMethod(String signatureAlgo, String certificateString, String didUrl, String kid) {
        PublicKey publicKey = loadPublicKeyFromCertificate(certificateString);
        Map<String, Object> verificationMethod = null;

        try {
            switch (signatureAlgo) {
                case JWSAlgorithm.ES256K:
                    verificationMethod = generateECK1VerificationMethod(publicKey, didUrl);
                    break;
                case JWSAlgorithm.EdDSA:
                    verificationMethod = generateEd25519VerificationMethod(publicKey, didUrl);
                    break;
                case JWSAlgorithm.RS256:
                    verificationMethod = generateRSAVerificationMethod(publicKey, didUrl);
                    break;
                case JWSAlgorithm.ES256:
                    verificationMethod = generateECR1VerificationMethod(publicKey, didUrl);
                    break;
                default:
                    log.error("Unsupported signature algorithm provided :" + signatureAlgo);
                    throw new CertifyException(ErrorConstants.UNSUPPORTED_ALGORITHM);
            }
        } catch(CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Exception occured while generating verification method for given certificate", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.VERIFICATION_METHOD_GENERATION_FAILED);
        }

        verificationMethod.put("id", didUrl + "#" + kid);
        return verificationMethod;
    }

    private static Map<String, Object> generateECR1VerificationMethod(PublicKey publicKey, String didUrl) {
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        BigInteger yBI = ecPublicKey.getW().getAffineY();
        byte prefixByte = yBI.testBit(0) ? (byte) 0x03 : (byte) 0x02;
        // Compressed format: 0x02 or 0x03 || X
        byte[] compressed = ByteBuffer.allocate(1 + 32)
                .put(prefixByte)
                .put(BigIntegers.asUnsignedByteArray(ecPublicKey.getW().getAffineX()))
                .array();

        // P-256 compressed public key multicodec prefix: 0x1201(varint form of 0x8024)
        byte[] prefix = HexFormat.of().parseHex("8024");
        byte[] finalBytes = new byte[prefix.length + compressed.length];
        System.arraycopy(prefix, 0, finalBytes, 0, prefix.length);
        System.arraycopy(compressed, 0, finalBytes, prefix.length, compressed.length);
        String publicKeyMultibase = Multibase.encode(Multibase.Base.Base58BTC, finalBytes);

        Map<String, Object> verificationMethod = new HashMap<>();
        verificationMethod.put("type", "EcdsaSecp256r1VerificationKey2019");
        verificationMethod.put("@context", "https://w3id.org/security/suites/ecdsa-2019/v1");
        verificationMethod.put("controller", didUrl);
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

     private static Map<String, Object> generateEd25519VerificationMethod(PublicKey publicKey, String didUrl) throws Exception {

        BCEdDSAPublicKey edKey = (BCEdDSAPublicKey) publicKey;
        byte[] rawBytes = edKey.getPointEncoding();
        byte[] multicodecBytes = HexFormat.of().parseHex(MULTICODEC_PREFIX);
        byte[] finalBytes = new byte[multicodecBytes.length + rawBytes.length];
        System.arraycopy(multicodecBytes, 0, finalBytes, 0, multicodecBytes.length);
        System.arraycopy(rawBytes, 0, finalBytes, multicodecBytes.length, rawBytes.length);
        String publicKeyMultibase = Multibase.encode(Multibase.Base.Base58BTC, finalBytes);
        
        Map<String, Object> verificationMethod = new HashMap<>();
        verificationMethod.put("type", "Ed25519VerificationKey2020");
        verificationMethod.put("@context", "https://w3id.org/security/suites/ed25519-2020/v1");
        verificationMethod.put("controller", didUrl);
        verificationMethod.put("publicKeyMultibase", publicKeyMultibase);
        return verificationMethod;
    }

    private static Map<String, Object> generateRSAVerificationMethod(PublicKey publicKey, String didUrl) throws Exception {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

        StringBuilder pemBuilder = new StringBuilder();
        pemBuilder.append("-----BEGIN PUBLIC KEY-----\n");
        pemBuilder.append(Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(rsaPublicKey.getEncoded()));
        pemBuilder.append("\n-----END PUBLIC KEY-----");

        Map<String, Object> verificationMethod = new HashMap<>();
        verificationMethod.put("type", "RsaVerificationKey2018");
        verificationMethod.put("@context", "https://w3id.org/security/v1");
        verificationMethod.put("controller", didUrl);
        verificationMethod.put("publicKeyPem", pemBuilder.toString());
        return verificationMethod;
    }

    private static Map<String, Object> generateECK1VerificationMethod(PublicKey publicKey, String didUrl) {
        // TODO: can validate the key or directly assume the curve here and
        //  go ahead or use P_256 only if `nimbusCurve` is having same value.
        ECKey nimbusKey = new ECKey.Builder(Curve.SECP256K1, (ECPublicKey) publicKey)
                .build();

        Map<String, Object> verificationMethod = new HashMap<>();
        // ref: https://github.com/w3c-ccg/lds-ecdsa-secp256k1-2019/issues/8
        verificationMethod.put("type", "EcdsaSecp256k1VerificationKey2019");
        verificationMethod.put("@context", "https://w3id.org/security/v1");
        // (improvement): can also add expires key here
        verificationMethod.put("controller", didUrl);
        verificationMethod.put("publicKeyJwk", nimbusKey.toJSONObject());
        // NOTE: Advice against using publicKeyHex by the spec author
        // ref: https://github.com/w3c-ccg/lds-ecdsa-secp256k1-2019/issues/4
        // ref: https://w3c.github.io/vc-data-integrity/vocab/security/vocabulary.html#publicKeyHex

        // As per the below spec, publicKeyBase58 is also supported
        // ref: https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1signature2019
        return verificationMethod;
    }

    @Cacheable(value = "certificatedatacache", key = "#appId + '-' + #refId")
    public CertificateResponseDTO getCertificateDataResponseDto(String appId, String refId) {
        AllCertificatesDataResponseDto kidResponse = keymanagerService.getAllCertificates(appId, Optional.of(refId));
        if (kidResponse == null || kidResponse.getAllCertificates() == null || kidResponse.getAllCertificates().length == 0) {
            log.error("No certificates found for appId: {} and refId: {}", appId, refId);
            throw new CertifyException("No certificates found");
        }

        CertificateDataResponseDto certificateData = Arrays.stream(kidResponse.getAllCertificates())
                .filter(certificateDataResponseDto -> certificateDataResponseDto.getExpiryAt() != null
                        && certificateDataResponseDto.getExpiryAt().isAfter(LocalDateTime.now()))
                .max(Comparator.comparing(CertificateDataResponseDto::getExpiryAt))
                .orElseThrow(() -> {
                    log.error("No valid certificates found for appId: {} and refId: {}", appId, refId);
                    return new CertifyException("No valid certificates found");
                });

        CertificateResponseDTO certificateResponseDTO = new CertificateResponseDTO();
        certificateResponseDTO.setCertificateData(certificateData.getCertificateData());
        certificateResponseDTO.setKeyId(certificateData.getKeyId());

        return certificateResponseDTO;
    }

    private Map<String, List<String>> getSignatureCryptoSuiteMap() {
        // Fetch all credential configurations
        List<CredentialConfig> allConfigs = credentialConfigRepository.findAll();

        // Create a map with signatureCryptoSuite as the key and appId, refId as values
        Map<String, List<String>> signatureCryptoSuiteMap = new HashMap<>();
        for (CredentialConfig config : allConfigs) {
            String appId = config.getKeyManagerAppId();
            String refId = config.getKeyManagerRefId();

            if(appId != null) {
                String uniqueKey = appId + "-" + (refId != null ? refId : "");
                List<String> configDetails = new ArrayList<>();
                configDetails.add(appId);
                configDetails.add(refId);
                if (config.getSignatureAlgo() == null) {
                    String signatureCryptoSuite = config.getSignatureCryptoSuite();
                    configDetails.add(credentialSigningAlgValuesSupportedMap.get(signatureCryptoSuite).getFirst());
                } else {
                    configDetails.add(config.getSignatureAlgo());
                }

                signatureCryptoSuiteMap.put(uniqueKey, configDetails);
            }
        }

        return signatureCryptoSuiteMap;
    }
}
