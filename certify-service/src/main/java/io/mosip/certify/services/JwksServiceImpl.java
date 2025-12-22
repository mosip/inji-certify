package io.mosip.certify.services;

import com.nimbusds.jose.jwk.JWK;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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

@Service
@Slf4j
public class JwksServiceImpl implements JwksService {

    @Autowired
    private KeymanagerService keymanagerService;

    /**
     * Internal method to fetch JWK set - cached for performance
     * Only successful responses are cached (method returns non-null Map)
     */
    @Cacheable(value = "jwks", key = "'oauth-jwks'")
    public Map<String, Object> getJwks() {
        AllCertificatesDataResponseDto allCertificatesDataResponseDto = keymanagerService.getAllCertificates(
                KeyManagerConstants.CERTIFY_SERVICE_APP_ID, Optional.empty());

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

        Map<String, Object> response = new HashMap<>();
        response.put("keys", jwkList);

        return response;
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
        map.put("e", jwk.toPublicJWK().getRequiredParams().get("e"));
        map.put("n", jwk.toPublicJWK().getRequiredParams().get("n"));
        return map;
    }
}
