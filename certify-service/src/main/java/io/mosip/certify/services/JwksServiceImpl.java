package io.mosip.certify.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.*;

import static io.mosip.certify.core.constants.Constants.CERTIFY_SERVICE_APP_ID;
import static io.mosip.certify.core.constants.Constants.ED25519_REF_ID;

@Service
@Slf4j
public class JwksServiceImpl implements JwksService {

    private final KeymanagerService keymanagerService;

    private final CredentialConfigRepository credentialConfigRepository;

    @Value("#{${mosip.certify.credential-config.credential-signing-alg-values-supported}}")
    private LinkedHashMap<String, List<String>> credentialSigningAlgValuesSupportedMap;

    @Value("#{${mosip.certify.signature-algo.key-alias-mapper:{}}}")
    private Map<String, List<List<String>>> signatureAlgoKeyAliasMapper;

    @Autowired
    public JwksServiceImpl(KeymanagerService keymanagerService,
                           CredentialConfigRepository credentialConfigRepository) {
        this.keymanagerService = keymanagerService;
        this.credentialConfigRepository = credentialConfigRepository;
    }

    /**
     * Internal method to fetch JWK set - cached for performance
     * Only successful responses are cached (method returns non-null Map)
     */
    @Cacheable(value = "jwks", key = "'oauth-jwks'")
    public Map<String, Object> getJwks() {
        List<Map<String, Object>> jwkList = new ArrayList<>();

        // Fetch JWKs dynamically from configuration map
        signatureAlgoKeyAliasMapper.forEach((algo, keyAliases) -> {
            keyAliases.forEach(keyAlias -> {
                String appId = keyAlias.get(0);
                String refId = keyAlias.size() > 1 ? keyAlias.get(1) : "";
                AllCertificatesDataResponseDto response = keymanagerService.getAllCertificates(appId, Optional.of(refId));
                jwkList.addAll(getJwks(response));
            });
        });

        // Add jwks for CERTIFY_SERVICE_APP_ID
        AllCertificatesDataResponseDto responseDto = keymanagerService.getAllCertificates(CERTIFY_SERVICE_APP_ID, Optional.empty());
        jwkList.addAll(getJwks(responseDto));

        Map<String, Object> response = new HashMap<>();
        response.put("keys", jwkList);

        return response;
    }

    private List<Map<String, Object>> getJwks(AllCertificatesDataResponseDto allCertificatesDataResponseDto) {
        List<Map<String, Object>> jwkList = new ArrayList<>();
        if (allCertificatesDataResponseDto != null && allCertificatesDataResponseDto.getAllCertificates() != null) {
            Arrays.stream(allCertificatesDataResponseDto.getAllCertificates())
                    .filter(dto -> dto != null
                            && StringUtils.hasText(dto.getKeyId())
                            && StringUtils.hasText(dto.getCertificateData()))
                    .forEach(dto -> {
                        try {
                            Map<String, Object> jwk = getJwk(dto.getKeyId(), dto.getCertificateData(), dto.getExpiryAt());
                            if (jwk != null) {
                                jwkList.add(jwk);
                                log.debug("Added JWK for keyId: {}", dto.getKeyId());
                            }
                        } catch (Exception e) {
                            log.error("Failed to parse the certificate data for keyId: {}", dto.getKeyId(), e);
                            // Continue processing other certificates
                        }
                    });
        } else {
            log.warn("No certificates found for CERTIFY_SERVICE_APP_ID");
        }
        return jwkList;
    }

    /**
     * Convert certificate data to JWK format
     *
     * @param keyId Key identifier
     * @param certificateData PEM encoded certificate
     * @param expiryAt Certificate expiry date
     * @return JWK map, or null if certificate parsing fails or certificate is expired
     * @throws Exception if certificate parsing fails
     */
    private Map<String, Object> getJwk(String keyId, String certificateData, LocalDateTime expiryAt) throws Exception {
        // Validate inputs
        if (!StringUtils.hasText(keyId)) {
            throw new IllegalArgumentException("keyId cannot be null or empty");
        }
        if (!StringUtils.hasText(certificateData)) {
            throw new IllegalArgumentException("certificateData cannot be null or empty");
        }

        // Validate certificate is not expired if expiryAt is provided
        if (expiryAt != null && expiryAt.isBefore(LocalDateTime.now())) {
            log.debug("Certificate for keyId: {} has expired, skipping", keyId);
            return null;
        }

        X509Certificate cert = parseCertificate(certificateData);
        /* ---------- ED25519 ---------- */
        if (isEd25519(cert)) {
            return buildEd25519Jwk(keyId, cert, expiryAt);
        }

        /* ---------- RSA / EC ---------- */
        JWK jwk = JWK.parseFromPEMEncodedX509Cert(certificateData);
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kid", keyId);
        if(jwk.getAlgorithm() != null) { map.put("alg", jwk.getAlgorithm().getName()); }
        map.put("kty", jwk.getKeyType().getValue());
        if(jwk.getKeyUse() != null) { map.put("use", jwk.getKeyUse().getValue()); }
        if(expiryAt != null) { map.put("exp", expiryAt.toEpochSecond(ZoneOffset.UTC)); }
        List<String> certs = new ArrayList<>();
        jwk.getX509CertChain().forEach(c -> { certs.add(c.toString()); });
        map.put("x5c", certs);
        map.put("x5t#S256", jwk.getX509CertSHA256Thumbprint().toString());
        Map<String, ?> jwkParams = jwk.toPublicJWK().getRequiredParams();
        if (jwkParams.containsKey("e")) map.put("e", jwkParams.get("e"));
        if (jwkParams.containsKey("n")) map.put("n", jwkParams.get("n"));

        // EC parameters
        if (jwkParams.containsKey("x")) map.put("x", jwkParams.get("x"));
        if (jwkParams.containsKey("y")) map.put("y", jwkParams.get("y"));
        if (jwkParams.containsKey("crv")) map.put("crv", jwkParams.get("crv"));
        return map;
    }

    private X509Certificate parseCertificate(String pem) throws Exception {
        String cleanPem = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        byte[] certBytes = Base64.getDecoder().decode(cleanPem);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    private boolean isEd25519(X509Certificate cert) {
        String algorithm = cert.getPublicKey().getAlgorithm();
        return JWSAlgorithm.EdDSA.getName().equalsIgnoreCase(algorithm) ||
                JWSAlgorithm.Ed25519.getName().equalsIgnoreCase(algorithm);
    }

    private List<String> buildX5c(X509Certificate cert) throws Exception {
        return List.of(
                Base64.getEncoder().encodeToString(cert.getEncoded())
        );
    }

    private String buildX5tS256(X509Certificate cert) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(cert.getEncoded());
        return Base64URL.encode(digest).toString();
    }

    private Map<String, Object> buildEd25519Jwk(String keyId, X509Certificate cert, LocalDateTime expiryAt) throws Exception {
        byte[] publicKeyBytes = cert.getPublicKey().getEncoded();
        // SPKI format for Ed25519: 12-byte ASN.1 header + 32-byte raw key
        // Extract the raw 32-byte Ed25519 public key from SPKI encoding
        if (publicKeyBytes.length != 44) {
            throw new CertifyException("Invalid Ed25519 public key length: expected 44 bytes (SPKI), got " + publicKeyBytes.length);
        }
        byte[] rawPublicKey = new byte[32];
        System.arraycopy(publicKeyBytes, 12, rawPublicKey, 0, 32);
        OctetKeyPair okp = new OctetKeyPair.Builder(
                Curve.Ed25519,
                Base64URL.encode(rawPublicKey)
        )
                .keyID(keyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .build();
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kid", keyId);
        map.put("kty", "OKP");
        map.put("crv", "Ed25519");
        map.put("x", okp.getX().toString());
        map.put("use", "sig");
        map.put("x5c", buildX5c(cert));
        map.put("x5t#S256", buildX5tS256(cert));
        if (expiryAt != null) {
            map.put("exp", expiryAt.toEpochSecond(ZoneOffset.UTC));
        }
        return map;
    }
}
