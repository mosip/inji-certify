package io.mosip.certify.repository;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.entity.Ledger;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class LedgerIssuanceTableCustomRepositoryImplTest {

    @Mock
    private EntityManager entityManager;

    @Mock
    private Query query;

    private LedgerIssuanceTableCustomRepositoryImpl repository;

    @Before
    public void setUp() throws Exception {
        repository = new LedgerIssuanceTableCustomRepositoryImpl(new ObjectMapper());
        Field emField = LedgerIssuanceTableCustomRepositoryImpl.class.getDeclaredField("entityManager");
        emField.setAccessible(true);
        emField.set(repository, entityManager);
    }

    private CredentialLedgerSearchRequest baseRequest() {
        CredentialLedgerSearchRequest req = new CredentialLedgerSearchRequest();
        req.setIssuerId("issuer-1");
        req.setCredentialType("MockType");
        return req;
    }

    @Test
    public void findBySearchRequest_baseQuery() {
        when(entityManager.createNativeQuery(anyString(), eq(Ledger.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of(new Ledger()));

        List<Ledger> result = repository.findBySearchRequest(baseRequest());

        assertEquals(1, result.size());
        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        verify(entityManager).createNativeQuery(sqlCaptor.capture(), eq(Ledger.class));
        String sql = sqlCaptor.getValue();
        assertTrue(sql.contains("issuer_id = :issuerId"));
        assertTrue(sql.contains("credential_type = :credentialType"));
        assertFalse(sql.contains("credential_id ="));
        verify(query).setParameter("issuerId", "issuer-1");
        verify(query).setParameter("credentialType", "MockType");
    }

    @Test
    public void findBySearchRequest_withCredentialId() {
        CredentialLedgerSearchRequest req = baseRequest();
        req.setCredentialId("cred-123");
        when(entityManager.createNativeQuery(anyString(), eq(Ledger.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of());

        repository.findBySearchRequest(req);

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        verify(entityManager).createNativeQuery(sqlCaptor.capture(), eq(Ledger.class));
        assertTrue(sqlCaptor.getValue().contains("credential_id = :credentialId"));
        verify(query).setParameter("credentialId", "cred-123");
    }

    @Test
    public void findBySearchRequest_withIndexedAttributes_skipsBlankEntries() {
        CredentialLedgerSearchRequest req = baseRequest();
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("policyNumber", "12345");
        attrs.put("blankKey", "  ");   // skipped: blank value
        attrs.put("  ", "value");      // skipped: blank key
        req.setIndexedAttributesEquals(attrs);

        when(entityManager.createNativeQuery(anyString(), eq(Ledger.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of());

        repository.findBySearchRequest(req);

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        verify(entityManager).createNativeQuery(sqlCaptor.capture(), eq(Ledger.class));
        String sql = sqlCaptor.getValue();
        // Only one indexed attribute should be appended (indexedAttr0)
        assertTrue(sql.contains(":indexedAttr0"));
        assertFalse(sql.contains(":indexedAttr1"));
        verify(query).setParameter(eq("indexedAttr0"), any());
    }

    @Test
    public void findBySearchRequest_wrapsExceptions() {
        when(entityManager.createNativeQuery(anyString(), eq(Ledger.class)))
                .thenThrow(new IllegalStateException("db down"));

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> repository.findBySearchRequest(baseRequest()));
        assertTrue(ex.getMessage().contains("Failed to search LedgerIssuanceTable"));
    }
}
