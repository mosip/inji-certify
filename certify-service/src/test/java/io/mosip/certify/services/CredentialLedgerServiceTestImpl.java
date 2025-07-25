package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.repository.LedgerRepository;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CredentialLedgerServiceTestImpl {
    @Mock
    private LedgerRepository ledgerRepository;

    @InjectMocks
    private CredentialLedgerServiceImpl ledgerService;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void searchCredentials_ValidRequestWithAllFields_ReturnsResult() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setCredentialId("67823e96-fda0-4eba-9828-a32a8d22cc42");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        Ledger ledger = createLedger("67823e96-fda0-4eba-9828-a32a8d22cc42");
        when(ledgerRepository.findBySearchRequest(request)).thenReturn(List.of(ledger));

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedger(request);

        Assert.assertEquals(1, results.size());
        Assert.assertEquals("67823e96-fda0-4eba-9828-a32a8d22cc42", results.get(0).getCredentialId());
    }

    @Test
    public void searchCredentials_ValidRequestNoResults_ReturnsEmptyList() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientName", "Unknown"));

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(Collections.emptyList());

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedger(request);

        assertTrue(results.isEmpty());
    }

    @Test
    public void searchCredentials_NullIndexedAttrs_ThrowsCertifyException() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(null);

        CertifyException ex = assertThrows(CertifyException.class, () -> ledgerService.searchCredentialLedger(request));
        Assert.assertEquals("INVALID_SEARCH_CRITERIA", ex.getErrorCode());
    }

    @Test
    public void searchCredentials_EmptyIndexedAttrs_ThrowsCertifyException() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Collections.emptyMap());

        CertifyException ex = assertThrows(CertifyException.class, () -> ledgerService.searchCredentialLedger(request));
        Assert.assertEquals("INVALID_SEARCH_CRITERIA", ex.getErrorCode());
    }

    @Test
    public void searchCredentials_RepositoryThrowsException_ThrowsCertifyException() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        when(ledgerRepository.findBySearchRequest(request)).thenThrow(new RuntimeException("DB error"));

        CertifyException ex = assertThrows(CertifyException.class, () -> ledgerService.searchCredentialLedger(request));
        Assert.assertEquals("SEARCH_CREDENTIALS_FAILED", ex.getErrorCode());
    }

    private Ledger createLedger(String credentialId) {
        Ledger ledger = new Ledger();
        ledger.setId(1L);
        ledger.setCredentialId(credentialId);
        ledger.setIssuerId("did:web:Nandeesh778.github.io:local-test:certify_did");
        ledger.setIssueDate(OffsetDateTime.parse("2025-06-10T10:23:24Z"));
        ledger.setExpirationDate(null);
        ledger.setCredentialType("VerifiableCredential");
        ledger.setCredentialStatusDetails(new ArrayList<>());
        return ledger;
    }

}
