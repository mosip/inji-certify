package io.mosip.certify;

import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.services.VCICacheService;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

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

    @InjectMocks
    private VCICacheService vciCacheService = new VCICacheService();

    private static final String TEST_ACCESS_TOKEN_HASH = "testHash123";
    private static final String VCISSUANCE_CACHE = "vcissuance";

    @Before
    public void setup() {
        when(cacheManager.getCache(VCISSUANCE_CACHE)).thenReturn(cache);
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
        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce("test-cnonce");
        when(cache.get(TEST_ACCESS_TOKEN_HASH, VCIssuanceTransaction.class)).thenReturn(transaction);
        VCIssuanceTransaction result = vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH);
        assertEquals(transaction, result);
        verify(cacheManager).getCache(VCISSUANCE_CACHE);
        verify(cache).get(eq(TEST_ACCESS_TOKEN_HASH), eq(VCIssuanceTransaction.class));
    }

}
