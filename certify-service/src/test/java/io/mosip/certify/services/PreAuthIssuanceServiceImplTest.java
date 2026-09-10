package io.mosip.certify.services;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.PreAuthTransaction;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class PreAuthIssuanceServiceImplTest {

    @Mock
    private VCICacheService vciCacheService;

    @Mock
    private ParsedAccessToken parsedAccessToken;

    @InjectMocks
    private PreAuthIssuanceServiceImpl service;

    @Test
    public void fetchData_returnsClaimsFromCache() throws Exception {
        when(parsedAccessToken.getAccessTokenHash()).thenReturn("hash-1");
        PreAuthTransaction tx = new PreAuthTransaction();
        tx.setClaims(Map.of("name", "Alice", "age", 30));
        when(vciCacheService.getPreAuthTransaction("hash-1")).thenReturn(tx);

        JSONObject result = service.fetchData(Map.of());
        assertEquals("Alice", result.getString("name"));
        assertEquals(30, result.getInt("age"));
    }

    @Test
    public void fetchData_nullTokenHash_throws() {
        when(parsedAccessToken.getAccessTokenHash()).thenReturn(null);
        assertThrows(DataProviderExchangeException.class, () -> service.fetchData(Map.of()));
    }

    @Test
    public void fetchData_emptyTokenHash_throws() {
        when(parsedAccessToken.getAccessTokenHash()).thenReturn("");
        assertThrows(DataProviderExchangeException.class, () -> service.fetchData(Map.of()));
    }

    @Test
    public void fetchData_missingCachedTransaction_throws() {
        when(parsedAccessToken.getAccessTokenHash()).thenReturn("hash-1");
        when(vciCacheService.getPreAuthTransaction("hash-1")).thenReturn(null);
        assertThrows(DataProviderExchangeException.class, () -> service.fetchData(Map.of()));
    }

    @Test
    public void fetchData_nullClaims_throws() {
        when(parsedAccessToken.getAccessTokenHash()).thenReturn("hash-1");
        PreAuthTransaction tx = new PreAuthTransaction();
        tx.setClaims(null);
        when(vciCacheService.getPreAuthTransaction("hash-1")).thenReturn(tx);
        assertThrows(DataProviderExchangeException.class, () -> service.fetchData(Map.of()));
    }

    @Test
    public void fetchData_emptyClaims_throws() {
        when(parsedAccessToken.getAccessTokenHash()).thenReturn("hash-1");
        PreAuthTransaction tx = new PreAuthTransaction();
        tx.setClaims(Map.of());
        when(vciCacheService.getPreAuthTransaction("hash-1")).thenReturn(tx);
        assertThrows(DataProviderExchangeException.class, () -> service.fetchData(Map.of()));
    }
}
