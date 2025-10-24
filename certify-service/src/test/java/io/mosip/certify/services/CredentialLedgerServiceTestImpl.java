package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusDetail;
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

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

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

    @Test
    public void storeLedgerEntry_Success() {
        CredentialStatusDetail detail = new CredentialStatusDetail();
        Map<String, Object> attrs = Collections.singletonMap("foo", "bar");
        ledgerService.storeLedgerEntry("cid", "issuer", "ctype", detail, attrs, LocalDateTime.now());
        verify(ledgerRepository).save(any(Ledger.class));
    }

    @Test
    public void storeLedgerEntry_Error_Throws() {
        doThrow(new RuntimeException("fail")).when(ledgerRepository).save(any());
        try {
            ledgerService.storeLedgerEntry("cid", "issuer", "ctype", new CredentialStatusDetail(), Collections.emptyMap(), LocalDateTime.now());
            fail("Expected RuntimeException");
        } catch (RuntimeException ex) {
            // expected
        }
    }

    @Test
    public void searchCredentials_RepositoryReturnsNull_ThrowsCertifyException() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(null);

        CertifyException ex = assertThrows(CertifyException.class, () -> ledgerService.searchCredentialLedger(request));
        assertEquals("SEARCH_CREDENTIALS_FAILED", ex.getErrorCode());
    }


    @Test
    public void searchCredentials_LedgerWithNullOrEmptyDetails_ReturnsSingleResponse() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        Ledger ledgerWithNullDetails = createLedger("id-null");
        ledgerWithNullDetails.setCredentialStatusDetails(null);

        Ledger ledgerWithEmptyDetails = createLedger("id-empty");
        ledgerWithEmptyDetails.setCredentialStatusDetails(Collections.emptyList());

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(List.of(ledgerWithNullDetails, ledgerWithEmptyDetails));

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedger(request);
        assertEquals(2, results.size());
        assertEquals("id-null", results.get(0).getCredentialId());
        assertEquals("id-empty", results.get(1).getCredentialId());
    }

    @Test
    public void searchCredentials_LedgerWithMultipleStatusDetails_ReturnsMultipleResponses() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        Ledger ledger = createLedger("multi-details");
        CredentialStatusDetail detail1 = new CredentialStatusDetail();
        detail1.setStatusPurpose("ACTIVE");
        detail1.setStatusListCredentialId("list1");
        detail1.setStatusListIndex(1L);
        detail1.setCreatedTimes(100L);

        CredentialStatusDetail detail2 = new CredentialStatusDetail();
        detail2.setStatusPurpose("REVOKED");
        detail2.setStatusListCredentialId("list2");
        detail2.setStatusListIndex(2L);
        detail2.setCreatedTimes(200L);

        ledger.setCredentialStatusDetails(List.of(detail1, detail2));

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(List.of(ledger));

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedger(request);
        assertEquals(2, results.size());
        assertEquals("multi-details", results.get(0).getCredentialId());
        assertEquals("multi-details", results.get(1).getCredentialId());
        assertNotEquals(results.get(0).getStatusPurpose(), results.get(1).getStatusPurpose());
    }

    @Test
    public void searchCredentials_MixedNullAndNonNullStatusDetails_ReturnsCorrectResponses() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        Ledger ledger1 = createLedger("id-null");
        ledger1.setCredentialStatusDetails(null);

        Ledger ledger2 = createLedger("id-nonnull");
        CredentialStatusDetail detail = new CredentialStatusDetail();
        detail.setStatusPurpose("ACTIVE");
        detail.setStatusListCredentialId("list1");
        detail.setStatusListIndex(1L);
        detail.setCreatedTimes(100L);
        ledger2.setCredentialStatusDetails(List.of(detail));

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(List.of(ledger1, ledger2));

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedger(request);
        assertEquals(2, results.size());
        assertEquals("id-null", results.get(0).getCredentialId());
        assertEquals("id-nonnull", results.get(1).getCredentialId());
        assertEquals("ACTIVE", results.get(1).getStatusPurpose());
    }

    @Test
    public void searchCredentials_LedgerWithInvalidStatusDetail_ReturnsResponseWithNullStatusPurpose() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        Ledger ledger = createLedger("id-invalid");
        CredentialStatusDetail invalidDetail = new CredentialStatusDetail(); // statusPurpose not set
        ledger.setCredentialStatusDetails(List.of(invalidDetail));

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(List.of(ledger));

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedger(request);
        assertEquals(1, results.size());
        assertNull(results.get(0).getStatusPurpose());
    }

    @Test
    public void searchCredentialsV2_LedgerWithNullOrEmptyDetails_ReturnsSingleResponse() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        Ledger ledgerWithNullDetails = createLedger("id-null-v2");
        ledgerWithNullDetails.setCredentialStatusDetails(null);

        Ledger ledgerWithEmptyDetails = createLedger("id-empty-v2");
        ledgerWithEmptyDetails.setCredentialStatusDetails(Collections.emptyList());

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(List.of(ledgerWithNullDetails, ledgerWithEmptyDetails));

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedgerV2(request);
        assertEquals(2, results.size());
        assertEquals("id-null-v2", results.get(0).getCredentialId());
        assertEquals("id-empty-v2", results.get(1).getCredentialId());
    }

    @Test
    public void searchCredentialsV2_LedgerWithMultipleStatusDetails_ReturnsMultipleResponses() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        Ledger ledger = createLedger("multi-details-v2");
        CredentialStatusDetail detail1 = new CredentialStatusDetail();
        detail1.setStatusPurpose("ACTIVE");
        detail1.setStatusListCredentialId("list1");
        detail1.setStatusListIndex(1L);
        detail1.setCreatedTimes(100L);

        CredentialStatusDetail detail2 = new CredentialStatusDetail();
        detail2.setStatusPurpose("REVOKED");
        detail2.setStatusListCredentialId("list2");
        detail2.setStatusListIndex(2L);
        detail2.setCreatedTimes(200L);

        ledger.setCredentialStatusDetails(List.of(detail1, detail2));

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(List.of(ledger));

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedgerV2(request);
        assertEquals(2, results.size());
        assertEquals("multi-details-v2", results.get(0).getCredentialId());
        assertEquals("multi-details-v2", results.get(1).getCredentialId());
        assertNotEquals(results.get(0).getStatusPurpose(), results.get(1).getStatusPurpose());
    }

    @Test
    public void searchCredentialsV2_MixedNullAndNonNullStatusDetails_ReturnsCorrectResponses() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        Ledger ledger1 = createLedger("id-null-v2");
        ledger1.setCredentialStatusDetails(null);

        Ledger ledger2 = createLedger("id-nonnull-v2");
        CredentialStatusDetail detail = new CredentialStatusDetail();
        detail.setStatusPurpose("ACTIVE");
        detail.setStatusListCredentialId("list1");
        detail.setStatusListIndex(1L);
        detail.setCreatedTimes(100L);
        ledger2.setCredentialStatusDetails(List.of(detail));

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(List.of(ledger1, ledger2));

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedgerV2(request);
        assertEquals(2, results.size());
        assertEquals("id-null-v2", results.get(0).getCredentialId());
        assertEquals("id-nonnull-v2", results.get(1).getCredentialId());
        assertEquals("ACTIVE", results.get(1).getStatusPurpose());
    }

    @Test
    public void searchCredentialsV2_LedgerWithInvalidStatusDetail_ReturnsResponseWithNullStatusPurpose() {
        CredentialLedgerSearchRequest request = new CredentialLedgerSearchRequest();
        request.setIssuerId("did:web:test");
        request.setCredentialType("VerifiableCredential");
        request.setIndexedAttributesEquals(Map.of("recipientEmail", "abc@example.com"));

        Ledger ledger = createLedger("id-invalid-v2");
        CredentialStatusDetail invalidDetail = new CredentialStatusDetail(); // statusPurpose not set
        ledger.setCredentialStatusDetails(List.of(invalidDetail));

        when(ledgerRepository.findBySearchRequest(request)).thenReturn(List.of(ledger));

        List<CredentialStatusResponse> results = ledgerService.searchCredentialLedgerV2(request);
        assertEquals(1, results.size());
        assertNull(results.get(0).getStatusPurpose());
    }


    private Ledger createLedger(String credentialId) {
        Ledger ledger = new Ledger();
        ledger.setId(1L);
        ledger.setCredentialId(credentialId);
        ledger.setIssuerId("did:web:Nandeesh778.github.io:local-test:certify_did");
        ledger.setIssuanceDate(LocalDateTime.parse("2025-06-10T10:23:24"));
        ledger.setExpirationDate(null);
        ledger.setCredentialType("VerifiableCredential");
        ledger.setCredentialStatusDetails(new ArrayList<>());
        return ledger;
    }

}
