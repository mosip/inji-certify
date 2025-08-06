package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
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
import java.time.OffsetDateTime;
import java.util.*;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CredentialStatusServiceImplTest {
    @Mock
    private LedgerRepository ledgerRepository;
    @Mock
    private CredentialStatusTransactionRepository credentialStatusTransactionRepository;

    @InjectMocks
    private CredentialStatusServiceImpl credentialStatusService;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void updateCredential_CredentialIdNotFound_ThrowsException() {
        String credentialId = "124";
        String statusListCredential = "https://example.com/status-list/xyz";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(credentialId, statusListCredential);

        when(ledgerRepository.findByCredentialId(credentialId)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("404 NOT_FOUND \"Credential not found: " + credentialId + "\"", exception.getMessage());
    }

    @Test
    public void updateCredential_With_ExistingTransaction() {
        // Given
        String credentialId = "67823e96-fda0-4eba-9828-a32a8d22cc45";
        String statusListCredential = "https://example.com/status-list/xyz";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(credentialId, statusListCredential);

        Ledger ledger = createLedger(credentialId);

        // Existing transaction with old values
        CredentialStatusTransaction existingTransaction = new CredentialStatusTransaction();
        existingTransaction.setTransactionLogId(42L);
        existingTransaction.setCredentialId(credentialId);
        existingTransaction.setStatusPurpose("suspension"); // old value
        existingTransaction.setStatusValue(false);
        existingTransaction.setStatusListCredentialId("https://old.example.com/status");
        existingTransaction.setStatusListIndex(11111L);

        // Mocking
        when(ledgerRepository.findByCredentialId(credentialId)).thenReturn(Optional.of(ledger));

        // Simulate repository save just returns the same transaction (with updated fields)
        when(credentialStatusTransactionRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        CredentialStatusResponse result = credentialStatusService.updateCredentialStatus(request);

        // Then
        assertNotNull(result);

        CredentialStatusResponse response = result;
        assertEquals(credentialId, response.getCredentialId());
        assertEquals("revocation", response.getStatusPurpose());
        assertEquals(87823, response.getStatusListIndex().longValue());
        assertEquals(statusListCredential, response.getStatusListCredentialUrl());
        assertEquals("VerifiableCredential", response.getCredentialType());
        assertEquals(ledger.getIssueDate().toLocalDateTime(), response.getIssueDate());
        assertNull(response.getExpirationDate());
    }


    @Test
    public void updateCredential_WithValidRequest_UpdatesLedgerAndReturnsResponse() {
        String credentialId = "67823e96-fda0-4eba-9828-a32a8d22cc42";
        String statusListCredential = "https://example.com/status-list/xyz";

        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(credentialId, statusListCredential);
        Ledger ledger = createLedger(credentialId);
        CredentialStatusTransaction savedTransaction = createSavedTransaction(credentialId, statusListCredential);

        when(ledgerRepository.findByCredentialId(credentialId)).thenReturn(Optional.of(ledger));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
            .thenReturn(savedTransaction);

        CredentialStatusResponse result = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(result);

        CredentialStatusResponse response = result;
        assertEquals(credentialId, response.getCredentialId());
        assertEquals("revocation", response.getStatusPurpose());
        assertEquals(87823, response.getStatusListIndex().longValue());
        assertEquals("VerifiableCredential", response.getCredentialType());
        assertEquals(statusListCredential, response.getStatusListCredentialUrl());
        assertNotNull(response.getStatusTimestamp());

        verify(ledgerRepository).findByCredentialId(credentialId);
        verify(credentialStatusTransactionRepository).save(any(CredentialStatusTransaction.class));
    }

    private UpdateCredentialStatusRequest createValidUpdateCredentialRequest(String credentialId, String statusListCredential) {
        UpdateCredentialStatusRequest.CredentialStatusDto statusDto = new UpdateCredentialStatusRequest.CredentialStatusDto();
        statusDto.setId(statusListCredential + "#87823");
        statusDto.setType("BitstringStatusListEntry");
        statusDto.setStatusPurpose("revocation");
        statusDto.setStatusListIndex(87823L);
        statusDto.setStatusListCredential(statusListCredential);

        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        request.setCredentialId(credentialId);
        request.setCredentialStatus(statusDto);
        request.setStatus(true); // Mark as revoked
        request.setIndexAllocator("default");

        return request;
    }

    private CredentialStatusTransaction createSavedTransaction(String credentialId, String statusListCredential) {
        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setCredentialId(credentialId);
        transaction.setStatusPurpose("revocation");
        transaction.setStatusValue(true);
        transaction.setStatusListCredentialId(statusListCredential);
        transaction.setStatusListIndex(87823L);
        transaction.setCreatedDtimes(LocalDateTime.parse("2025-06-11T11:41:30.236"));
        return transaction;
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
