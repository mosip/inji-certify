package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialOfferResponse;
import io.mosip.certify.core.dto.PreAuthCodeData;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachePut;
import org.springframework.data.redis.cache.RedisCache;
import org.springframework.stereotype.Service;
import io.mosip.certify.services.CredentialConfigurationServiceImpl;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class VCICacheService {

    @Autowired
    private CacheManager cacheManager;

    @Autowired
    private CredentialConfigurationServiceImpl credentialConfigurationService;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${spring.cache.type:simple}")
    private String cacheType;


    private static final String VCISSUANCE_CACHE = "vcissuance";
    private static final String METADATA_KEY = "metadata";

    @PostConstruct
    public void validateCacheConfiguration() {
        log.info("Cache type configured: {}", cacheType);

        if ("simple".equalsIgnoreCase(cacheType)) {
            log.warn("CRITICAL WARNING: Simple cache configured for production deployment " +
                    "'simple' cache uses in-memory storage isolated to each pod, " +
                    "Multi-pod deployments will experience cache inconsistencies and MAY BREAK FUNCTIONALLY, " +
                    "Current configuration: spring.cache.type=simple (in-memory, non-distributed), " +
                    "Switch to Redis cache for multi-pod deployments, Set spring.cache.type=redis in your configuration ");
        } else if ("redis".equalsIgnoreCase(cacheType)) {
            log.info("Redis cache is configured - suitable for multi-pod deployment");
        } else {
            log.warn("Unknown cache type configured: {}. Please verify configuration.", cacheType);
        }
    }


    @CachePut(value = VCISSUANCE_CACHE, key = "#accessTokenHash")
    public VCIssuanceTransaction setVCITransaction(String accessTokenHash, VCIssuanceTransaction vcIssuanceTransaction) {
        return vcIssuanceTransaction;
    }

    public VCIssuanceTransaction getVCITransaction(String accessTokenHash) {
        return cacheManager.getCache(VCISSUANCE_CACHE).get(accessTokenHash, VCIssuanceTransaction.class);
    }

    public void setPreAuthCodeData(String code, PreAuthCodeData data) {
        String key = Constants.PRE_AUTH_CODE_PREFIX + code;
        cacheManager.getCache("preAuthCodeCache").put(key, data);
    }

    public PreAuthCodeData getPreAuthCodeData(String code) {
        String key = Constants.PRE_AUTH_CODE_PREFIX + code;
        Cache.ValueWrapper wrapper = cacheManager.getCache("preAuthCodeCache").get(key);
        return wrapper != null ? (PreAuthCodeData) wrapper.get() : null;
    }

    public CredentialOfferResponse getCredentialOffer(String offerId) {
        String key = Constants.CREDENTIAL_OFFER_PREFIX + offerId;
        Cache cache = cacheManager.getCache("credentialOfferCache");

        if (cache == null) {
            return null;
        }

        Cache.ValueWrapper wrapper = cache.get(key);
        return wrapper != null ? (CredentialOfferResponse) wrapper.get() : null;
    }

    public void setCredentialOffer(String offerId, CredentialOfferResponse offer, int expirySeconds) {
        String key = Constants.CREDENTIAL_OFFER_PREFIX + offerId;
        Cache cache = cacheManager.getCache("credentialOfferCache");

        if (cache == null) {
            throw new IllegalStateException("credentialOfferCache not available");
        }

        // For Redis, use RedisCache.put with Duration
        if (cache instanceof RedisCache) {
            ((RedisCache) cache).put(key, offer);
        } else {
            // For simple cache, log warning and use basic put
            log.warn("TTL not supported for cache type: {}. Entry may not expire.", cacheType);
            cache.put(key, offer);
        }
    }

    /**
     * Get issuer metadata from cache. If not present, load from database.
     */
    public Map<String, Object> getIssuerMetadata() {
        Cache.ValueWrapper wrapper = cacheManager.getCache("issuerMetadataCache").get(METADATA_KEY);

        if (wrapper == null) {
            log.info("Issuer metadata not found in cache, loading from database...");
            try {
                var metadata = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

                // Convert DTOs to Map structure
                Map<String, Object> metadataMap = new HashMap<>();
                Map<String, Object> credentialConfigsMap = new HashMap<>();

                // Convert each CredentialConfigurationSupportedDTO to Map
                metadata.getCredentialConfigurationSupportedDTO().forEach((configId, configDTO) -> {
                    Map<String, Object> configMap = objectMapper.convertValue(configDTO, Map.class);
                    credentialConfigsMap.put(configId, configMap);
                });
                metadataMap.put(Constants.CREDENTIAL_CONFIGURATIONS_SUPPORTED, credentialConfigsMap);

                // Store in cache
                cacheManager.getCache("issuerMetadataCache").put(METADATA_KEY, metadataMap);

                log.info("Successfully loaded and cached issuer metadata with {} configurations", credentialConfigsMap.size());

                return metadataMap;
            } catch (Exception e) {
                log.error("Failed to load issuer metadata", e);
                throw new IllegalStateException("Failed to load issuer metadata", e);
            }
        }
        return (Map<String, Object>) wrapper.get();
    }
}