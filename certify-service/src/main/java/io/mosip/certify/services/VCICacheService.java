package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.NonceErrorConstants;
import io.mosip.certify.core.dto.CredentialOfferResponse;
import io.mosip.certify.core.dto.PreAuthCodeData;
import io.mosip.certify.core.dto.PreAuthTransaction;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.exception.CertifyException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachePut;
import org.springframework.data.redis.cache.RedisCache;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class VCICacheService {

    public enum PreAuthCodeClaimResult {
        CLAIMED,
        EXPIRED,
        INVALID_OR_USED
    }

    @Autowired
    private CacheManager cacheManager;

    @Value("${spring.cache.type:simple}")
    private String cacheType;

    private static final String VCISSUANCE_CACHE = "vcissuance";
    private static final String PRE_AUTH_TXN_CACHE = "preAuthCacheTxn";
    private static final String NONCE_CACHE = "nonce";

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
        Cache cache = cacheManager.getCache(VCISSUANCE_CACHE);
        if (cache == null) {
            log.error("Cache {} not available. Please verify cache configuration.", VCISSUANCE_CACHE);
            return null;
        }
        return cache.get(accessTokenHash, VCIssuanceTransaction.class);
    }

    @CachePut(value = PRE_AUTH_TXN_CACHE, key = "#accessTokenHash")
    public PreAuthTransaction setPreAuthTransaction(String accessTokenHash, PreAuthTransaction preAuthTransaction) {
        return preAuthTransaction;
    }

    public PreAuthTransaction getPreAuthTransaction(String accessTokenHash) {
        Cache cache = cacheManager.getCache(PRE_AUTH_TXN_CACHE);
        if (cache == null) {
            log.error("Cache {} not available. Please verify cache configuration.", PRE_AUTH_TXN_CACHE);
            return null;
        }
        return cache.get(accessTokenHash, PreAuthTransaction.class);
    }

    @CachePut(value = NONCE_CACHE, key = "'txn:' + #cNonce")
    public VCIssuanceTransaction setNonceTransaction(String cNonce, VCIssuanceTransaction transaction) {
        return transaction;
    }

    public VCIssuanceTransaction getNonceTransaction(String cNonce) {
        Cache cache = cacheManager.getCache(NONCE_CACHE);
        if (cache == null) {
            log.error("Cache {} not available. Please verify cache configuration.", NONCE_CACHE);
            throw new CertifyException(NonceErrorConstants.CACHE_NOT_AVAILABLE,
                    "Nonce cache is not configured. Please verify cache configuration.");
        }
        return cache.get("txn:" + cNonce, VCIssuanceTransaction.class);
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
            throw new IllegalStateException("credentialOfferCache not available");
        }

        Cache.ValueWrapper wrapper = cache.get(key);
        return wrapper != null ? (CredentialOfferResponse) wrapper.get() : null;
    }

    public void setCredentialOffer(String offerId, CredentialOfferResponse offer) {
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
     * Get cached authorization server metadata
     */
    public boolean isPreAuthCodeUsed(String code) {
        String key = "used:" + code;
        Cache cache = cacheManager.getCache("preAuthCodeCache");
        if (cache == null) {
            log.error("Cache preAuthCodeCache not available");
            return false;
        }
        Cache.ValueWrapper wrapper = cache.get(key);
        return wrapper != null && Boolean.TRUE.equals(wrapper.get());
    }

    public boolean claimPreAuthCode(String preAuthCode) {
        synchronized (this) {
            PreAuthCodeData codeData = getPreAuthCodeData(preAuthCode);
            if (codeData == null || isPreAuthCodeUsed(preAuthCode)) {
                return false;
            }
            markPreAuthCodeAsUsed(preAuthCode);
            return true;
        }
    }

    public PreAuthCodeClaimResult claimPreAuthCodeIfUnexpired(String preAuthCode, long currentTime) {
        synchronized (this) {
            PreAuthCodeData codeData = getPreAuthCodeData(preAuthCode);
            if (codeData == null || isPreAuthCodeUsed(preAuthCode)) {
                return PreAuthCodeClaimResult.INVALID_OR_USED;
            }

            if (codeData.getExpiresAt() < currentTime) {
                return PreAuthCodeClaimResult.EXPIRED;
            }

            markPreAuthCodeAsUsed(preAuthCode);
            return PreAuthCodeClaimResult.CLAIMED;
        }
    }

    /**
     * Mark a pre-authorized code as used to prevent reuse
     */
    public void markPreAuthCodeAsUsed(String code) {
        String key = "used:" + code;
        Cache cache = cacheManager.getCache("preAuthCodeCache");
        if (cache == null) {
            log.error("Cache preAuthCodeCache not available for marking code as used");
            return;
        }
        // Store in cache with same TTL as pre-auth code
        cache.put(key, true);

        // Also remove the pre-auth code data
        String codeKey = Constants.PRE_AUTH_CODE_PREFIX + code;
        cache.evict(codeKey);

        log.info("Pre-authorized code marked as used");
    }


}