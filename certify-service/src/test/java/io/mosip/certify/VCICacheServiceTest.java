package io.mosip.certify;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialOfferResponse;
import io.mosip.certify.core.dto.OAuthAuthorizationServerMetadataDTO;
import io.mosip.certify.core.dto.PreAuthCodeData;
import io.mosip.certify.core.dto.PreAuthTransaction;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.services.VCICacheService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.data.redis.cache.RedisCache;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class VCICacheServiceTest {
    @Mock
    private CacheManager cacheManager;

    @Mock
    private Cache cache;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private VCICacheService vciCacheService = new VCICacheService();

    private static final String TEST_ACCESS_TOKEN_HASH = "testHash123";
    private static final String VCISSUANCE_CACHE = "vcissuance";
    private static final String PRE_AUTH_CODE_CACHE = "preAuthCodeCache";
    private static final String CREDENTIAL_OFFER_CACHE = "credentialOfferCache";

    @Before
    public void setup() {
        when(cacheManager.getCache(anyString())).thenReturn(cache);
    }

    @Test
    public void setVCITransaction_ShouldReturnSameTransaction() {

        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce("test-cnonce");
        VCIssuanceTransaction result = vciCacheService.setVCITransaction(TEST_ACCESS_TOKEN_HASH, transaction);
        assertNotNull(result);
        assertEquals(transaction, result);
    }

    @Test
    public void getVCITransaction_WhenTransactionExists_ShouldReturnTransaction() {
        when(cacheManager.getCache(VCISSUANCE_CACHE)).thenReturn(cache);
        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce("test-cnonce");
        when(cache.get(TEST_ACCESS_TOKEN_HASH, VCIssuanceTransaction.class)).thenReturn(transaction);
        VCIssuanceTransaction result = vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH);
        assertEquals(transaction, result);
        verify(cacheManager).getCache(VCISSUANCE_CACHE);
        verify(cache).get(eq(TEST_ACCESS_TOKEN_HASH), eq(VCIssuanceTransaction.class));
    }

    @Test
    public void setPreAuthCodeData_Success() {
        String code = "test-code";
        PreAuthCodeData data = new PreAuthCodeData();
        vciCacheService.setPreAuthCodeData(code, data);
        verify(cacheManager).getCache(PRE_AUTH_CODE_CACHE);
        verify(cache).put(eq(Constants.PRE_AUTH_CODE_PREFIX + code), eq(data));
    }

    @Test
    public void getPreAuthCodeData_Success() {
        String code = "test-code";
        PreAuthCodeData data = new PreAuthCodeData();
        Cache.ValueWrapper wrapper = mock(Cache.ValueWrapper.class);
        when(wrapper.get()).thenReturn(data);
        when(cache.get(Constants.PRE_AUTH_CODE_PREFIX + code)).thenReturn(wrapper);

        PreAuthCodeData result = vciCacheService.getPreAuthCodeData(code);
        assertEquals(data, result);
    }

    @Test
    public void setCredentialOffer_Success() {
        String offerId = "test-offer-id";
        CredentialOfferResponse offer = new CredentialOfferResponse();
        vciCacheService.setCredentialOffer(offerId, offer);
        verify(cacheManager).getCache(CREDENTIAL_OFFER_CACHE);
        verify(cache).put(eq(Constants.CREDENTIAL_OFFER_PREFIX + offerId), eq(offer));
    }

    @Test
    public void getCredentialOffer_Success() {
        String offerId = "test-offer-id";
        CredentialOfferResponse offer = new CredentialOfferResponse();
        Cache.ValueWrapper wrapper = mock(Cache.ValueWrapper.class);
        when(wrapper.get()).thenReturn(offer);
        when(cache.get(Constants.CREDENTIAL_OFFER_PREFIX + offerId)).thenReturn(wrapper);

        CredentialOfferResponse result = vciCacheService.getCredentialOffer(offerId);
        assertEquals(offer, result);
    }

    @Test
    public void validateCacheConfiguration_Simple() {
        ReflectionTestUtils.setField(vciCacheService, "cacheType", "simple");
        vciCacheService.validateCacheConfiguration();
        // Just verifying no exception
    }

    @Test
    public void validateCacheConfiguration_Redis() {
        ReflectionTestUtils.setField(vciCacheService, "cacheType", "redis");
        vciCacheService.validateCacheConfiguration();
    }

    @Test
    public void validateCacheConfiguration_Unknown() {
        ReflectionTestUtils.setField(vciCacheService, "cacheType", "unknown");
        vciCacheService.validateCacheConfiguration();
    }

    @Test
    public void setCredentialOffer_RedisCache() {
        RedisCache redisCache = mock(RedisCache.class);
        when(cacheManager.getCache(CREDENTIAL_OFFER_CACHE)).thenReturn(redisCache);

        String offerId = "test-offer-id";
        CredentialOfferResponse offer = new CredentialOfferResponse();
        vciCacheService.setCredentialOffer(offerId, offer);

        verify(redisCache).put(eq(Constants.CREDENTIAL_OFFER_PREFIX + offerId), eq(offer));
    }

    // Tests for cache null handling

    @Test
    public void getVCITransaction_WhenCacheIsNull_ReturnsNull() {
        when(cacheManager.getCache(VCISSUANCE_CACHE)).thenReturn(null);

        VCIssuanceTransaction result = vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH);

        assertEquals(null, result);
        verify(cacheManager).getCache(VCISSUANCE_CACHE);
    }

    @Test(expected = IllegalStateException.class)
    public void getCredentialOffer_WhenCacheIsNull_ThrowsIllegalStateException() {
        when(cacheManager.getCache(CREDENTIAL_OFFER_CACHE)).thenReturn(null);

        vciCacheService.getCredentialOffer("test-offer-id");
    }

    @Test(expected = IllegalStateException.class)
    public void setCredentialOffer_WhenCacheIsNull_ThrowsIllegalStateException() {
        when(cacheManager.getCache(CREDENTIAL_OFFER_CACHE)).thenReturn(null);

        vciCacheService.setCredentialOffer("test-offer-id", new CredentialOfferResponse());
    }

    @Test
    public void getCredentialOffer_WhenNotFound_ReturnsNull() {
        String offerId = "test-offer-id";
        when(cacheManager.getCache(CREDENTIAL_OFFER_CACHE)).thenReturn(cache);
        when(cache.get(Constants.CREDENTIAL_OFFER_PREFIX + offerId)).thenReturn(null);

        CredentialOfferResponse result = vciCacheService.getCredentialOffer(offerId);

        assertEquals(null, result);
    }

    // Tests for setTransaction

    @Test
    public void setPreAuthTransaction_ShouldReturnSameTransaction_PreAuth() {
        String accessToken = "test-access-token";
        PreAuthTransaction transaction = new PreAuthTransaction();
        transaction.setCredentialConfigurationId("test-config");
        transaction.setClaims(java.util.Collections.emptyMap());

        PreAuthTransaction result = vciCacheService.setPreAuthTransaction(accessToken, transaction);

        assertNotNull(result);
        assertEquals(transaction, result);
    }

    // Tests for setASMetadata and getASMetadata

    private static final String AS_METADATA_CACHE = "asMetadataCache";

    // Tests for isPreAuthCodeUsed

    @Test
    public void isPreAuthCodeUsed_WhenUsed_ReturnsTrue() {
        String code = "used-code";
        String key = "used:" + code;
        Cache.ValueWrapper wrapper = mock(Cache.ValueWrapper.class);
        when(wrapper.get()).thenReturn(Boolean.TRUE);
        when(cacheManager.getCache(PRE_AUTH_CODE_CACHE)).thenReturn(cache);
        when(cache.get(key)).thenReturn(wrapper);

        boolean result = vciCacheService.isPreAuthCodeUsed(code);

        assertEquals(true, result);
        verify(cache).get(key);
    }

    @Test
    public void isPreAuthCodeUsed_WhenNotUsed_ReturnsFalse() {
        String code = "valid-code";
        String key = "used:" + code;
        when(cacheManager.getCache(PRE_AUTH_CODE_CACHE)).thenReturn(cache);
        when(cache.get(key)).thenReturn(null);

        boolean result = vciCacheService.isPreAuthCodeUsed(code);

        assertEquals(false, result);
        verify(cache).get(key);
    }

    @Test
    public void isPreAuthCodeUsed_WhenWrapperReturnsFalse_ReturnsFalse() {
        String code = "code";
        String key = "used:" + code;
        Cache.ValueWrapper wrapper = mock(Cache.ValueWrapper.class);
        when(wrapper.get()).thenReturn(Boolean.FALSE);
        when(cacheManager.getCache(PRE_AUTH_CODE_CACHE)).thenReturn(cache);
        when(cache.get(key)).thenReturn(wrapper);

        boolean result = vciCacheService.isPreAuthCodeUsed(code);

        assertEquals(false, result);
    }

    @Test
    public void markPreAuthCodeAsUsed_Success() {
        String code = "code-to-mark";
        String usedKey = "used:" + code;
        String codeKey = Constants.PRE_AUTH_CODE_PREFIX + code;
        when(cacheManager.getCache(PRE_AUTH_CODE_CACHE)).thenReturn(cache);

        vciCacheService.markPreAuthCodeAsUsed(code);

        verify(cache).put(eq(usedKey), eq(true));
        verify(cache).evict(eq(codeKey));
    }

    @Test
    public void getPreAuthTransaction_found() {
        PreAuthTransaction tx = new PreAuthTransaction();
        when(cache.get("h", PreAuthTransaction.class)).thenReturn(tx);
        assertEquals(tx, vciCacheService.getPreAuthTransaction("h"));
    }

    @Test
    public void getPreAuthTransaction_nullCache_returnsNull() {
        when(cacheManager.getCache("preAuthCacheTxn")).thenReturn(null);
        assertNull(vciCacheService.getPreAuthTransaction("h"));
    }

    @Test
    public void setPreAuthTransaction_returnsSame() {
        PreAuthTransaction tx = new PreAuthTransaction();
        assertEquals(tx, vciCacheService.setPreAuthTransaction("h", tx));
    }

    @Test
    public void setNonceTransaction_returnsSame() {
        VCIssuanceTransaction tx = new VCIssuanceTransaction();
        assertEquals(tx, vciCacheService.setNonceTransaction("nonce", tx));
    }

    @Test
    public void getNonceTransaction_found() {
        VCIssuanceTransaction tx = new VCIssuanceTransaction();
        when(cache.get("txn:nonce", VCIssuanceTransaction.class)).thenReturn(tx);
        assertEquals(tx, vciCacheService.getNonceTransaction("nonce"));
    }

    @Test
    public void getNonceTransaction_nullCache_throws() {
        when(cacheManager.getCache("nonce")).thenReturn(null);
        assertThrows(CertifyException.class, () -> vciCacheService.getNonceTransaction("nonce"));
    }

    @Test
    public void markPreAuthCodeAsUsed_nullCache_noOp() {
        when(cacheManager.getCache("preAuthCodeCache")).thenReturn(null);
        vciCacheService.markPreAuthCodeAsUsed("code");
    }

    @Test
    public void isPreAuthCodeUsed_nullCache_returnsFalse() {
        when(cacheManager.getCache("preAuthCodeCache")).thenReturn(null);
        assertFalse(vciCacheService.isPreAuthCodeUsed("code"));
    }

    @Test
    public void claimPreAuthCode_noData_returnsFalse() {
        when(cache.get("pre_auth_code:code")).thenReturn(null);
        assertFalse(vciCacheService.claimPreAuthCode("code"));
    }

    @Test
    public void claimPreAuthCode_validUnused_marksAndReturnsTrue() {
        PreAuthCodeData data = new PreAuthCodeData();
        Cache.ValueWrapper dataWrapper = mock(Cache.ValueWrapper.class);
        when(dataWrapper.get()).thenReturn(data);
        when(cache.get("pre_auth_code:code")).thenReturn(dataWrapper);
        when(cache.get("used:code")).thenReturn(null);

        assertTrue(vciCacheService.claimPreAuthCode("code"));
        verify(cache).put("used:code", true);
    }

    @Test
    public void claimPreAuthCode_alreadyUsed_returnsFalse() {
        PreAuthCodeData data = new PreAuthCodeData();
        Cache.ValueWrapper dataWrapper = mock(Cache.ValueWrapper.class);
        when(dataWrapper.get()).thenReturn(data);
        Cache.ValueWrapper usedWrapper = mock(Cache.ValueWrapper.class);
        when(usedWrapper.get()).thenReturn(Boolean.TRUE);
        when(cache.get("pre_auth_code:code")).thenReturn(dataWrapper);
        when(cache.get("used:code")).thenReturn(usedWrapper);

        assertFalse(vciCacheService.claimPreAuthCode("code"));
    }
}

