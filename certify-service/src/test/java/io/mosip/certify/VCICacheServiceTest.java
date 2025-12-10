package io.mosip.certify;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialIssuerMetadataVD13DTO;
import io.mosip.certify.core.dto.CredentialOfferResponse;
import io.mosip.certify.core.dto.PreAuthCodeData;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.services.CredentialConfigurationServiceImpl;
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

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class VCICacheServiceTest {
    @Mock
    private CacheManager cacheManager;

    @Mock
    private Cache cache;

    @Mock
    private CredentialConfigurationServiceImpl credentialConfigurationService;

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
    public void getIssuerMetadata_CacheHit() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("key", "value");
        Cache.ValueWrapper wrapper = mock(Cache.ValueWrapper.class);
        when(wrapper.get()).thenReturn(metadata);
        when(cache.get("metadata")).thenReturn(wrapper);

        Map<String, Object> result = vciCacheService.getIssuerMetadata();
        assertEquals(metadata, result);
        verify(credentialConfigurationService, never()).fetchCredentialIssuerMetadata(anyString());
    }

    @Test
    public void getIssuerMetadata_CacheMiss() {
        when(cache.get("metadata")).thenReturn(null);
        CredentialIssuerMetadataVD13DTO metadataDTO = new CredentialIssuerMetadataVD13DTO();
        metadataDTO.setCredentialConfigurationSupportedDTO(new HashMap<>());
        when(credentialConfigurationService.fetchCredentialIssuerMetadata("latest")).thenReturn(metadataDTO);

        Map<String, Object> result = vciCacheService.getIssuerMetadata();
        assertNotNull(result);
        verify(credentialConfigurationService).fetchCredentialIssuerMetadata("latest");
        verify(cache).put(eq("metadata"), anyMap());
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

    @Test(expected = IllegalStateException.class)
    public void getIssuerMetadata_WhenCacheIsNull_ThrowsIllegalStateException() {
        when(cacheManager.getCache("issuerMetadataCache")).thenReturn(null);

        vciCacheService.getIssuerMetadata();
    }

    @Test
    public void getCredentialOffer_WhenNotFound_ReturnsNull() {
        String offerId = "test-offer-id";
        when(cacheManager.getCache(CREDENTIAL_OFFER_CACHE)).thenReturn(cache);
        when(cache.get(Constants.CREDENTIAL_OFFER_PREFIX + offerId)).thenReturn(null);

        CredentialOfferResponse result = vciCacheService.getCredentialOffer(offerId);

        assertEquals(null, result);
    }
}

