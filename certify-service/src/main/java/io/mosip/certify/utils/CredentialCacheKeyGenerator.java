package io.mosip.certify.utils;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static io.mosip.certify.core.constants.Constants.DELIMITER;

@Component("credentialCacheKeyGenerator") // Bean name used in SpEL
public class CredentialCacheKeyGenerator {

    private static final Logger log = LoggerFactory.getLogger(CredentialCacheKeyGenerator.class);
    private final CredentialConfigRepository credentialConfigRepository;

    private final CacheManager cacheManager;

    public CredentialCacheKeyGenerator(CredentialConfigRepository credentialConfigRepository,
                                       CacheManager cacheManager) {
        this.credentialConfigRepository = credentialConfigRepository;
        this.cacheManager = cacheManager;
    }

    public String generateKeyFromCredentialConfigKeyId(String credentialConfigKeyId) {
        if (credentialConfigKeyId == null) {
            log.warn("generateKeyFromConfigId called with null configId for cache key generation.");
            return null;
        }

        Optional<CredentialConfig> configOpt = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if (configOpt.isPresent()) {
           CredentialConfig config = configOpt.get();

           if(config.getCredentialFormat().equals(VCFormats.DC_SD_JWT)){
                return String.join(DELIMITER,
                          config.getCredentialFormat(),
                          config.getSdJwtVct());
           }

           return String.join(DELIMITER,
                       config.getCredentialType(),
                       config.getContext(),
                       config.getCredentialFormat());
        }

        return  "default-key";
    }
}