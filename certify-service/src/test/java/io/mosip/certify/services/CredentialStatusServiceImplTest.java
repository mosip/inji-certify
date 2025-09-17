package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CredentialStatusServiceImplTest {

    @Mock
    private CredentialStatusTransactionRepository credentialStatusTransactionRepository;

    @Mock
    private StatusListCredentialRepository statusListCredentialRepository;

    @InjectMocks
    private CredentialStatusServiceImpl credentialStatusService;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        ReflectionTestUtils.setField(credentialStatusService, "allowedCredentialStatusPurposes", List.of("revocation", "purpose2"));
        ReflectionTestUtils.setField(credentialStatusService, "didUrl", "did:web:example.com:issuer");
    }

    // --- New Tests ---

    @Test
    public void updateCredentialStatus_WithValidRequest_SavesTransactionAndReturnsResponse() {
        // Arrange
        String statusListCredentialId = "https://example.com/status-list/xyz";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredentialId, "revocation");
        StatusListCredential statusListCredential = createStatusListCredential(statusListCredentialId, "revocation");
        CredentialStatusTransaction savedTransaction = createSavedTransaction(statusListCredentialId);

        when(statusListCredentialRepository.findById(statusListCredentialId)).thenReturn(Optional.of(statusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class))).thenReturn(savedTransaction);

        // Act
        CredentialStatusResponse result = credentialStatusService.updateCredentialStatus(request);

        // Assert
        assertNotNull(result);
        assertEquals("did:web:example.com:issuer", result.getIssuerId());
        assertEquals(statusListCredentialId, result.getStatusListCredentialUrl());
        assertEquals(87823L, result.getStatusListIndex());
        assertEquals("revocation", result.getStatusPurpose());
        assertNotNull(result.getStatusTimestamp());

        verify(statusListCredentialRepository).findById(statusListCredentialId);
        verify(credentialStatusTransactionRepository).save(any(CredentialStatusTransaction.class));
    }

    @Test
    public void updateCredentialStatus_InvalidStatusPurpose_ThrowsCertifyException() {
        // Arrange
        String statusListCredentialId = "https://example.com/status-list/abc";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredentialId, "invalid-purpose");

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });
        assertEquals("Invalid credential status purpose. Allowed values are: [revocation, purpose2]", exception.getMessage());
    }

    @Test
    public void updateCredentialStatus_StatusListCredentialNotFound_ThrowsResponseStatusException() {
        // Arrange
        String statusListCredentialId = "https://example.com/status-list/non-existent";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredentialId, "revocation");

        when(statusListCredentialRepository.findById(statusListCredentialId)).thenReturn(Optional.empty());

        // Act & Assert
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("404 NOT_FOUND \"StatusListCredential not found with id: " + statusListCredentialId + "\"", exception.getMessage());
    }

    @Test
    public void updateCredentialStatus_NullStatusPurpose_UsesPurposeFromStatusListCredential() {
        // Arrange
        String statusListCredentialId = "https://example.com/status-list/def";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredentialId, null);
        StatusListCredential statusListCredential = createStatusListCredential(statusListCredentialId, "revocation");
        CredentialStatusTransaction savedTransaction = createSavedTransaction(statusListCredentialId);

        when(statusListCredentialRepository.findById(statusListCredentialId)).thenReturn(Optional.of(statusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class))).thenReturn(savedTransaction);

        // Act
        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        // Assert
        assertNotNull(response);
        assertEquals("revocation", response.getStatusPurpose());
    }

    // --- Helper Methods ---

    private UpdateCredentialStatusRequest createValidUpdateCredentialRequest(String statusListCredential, String statusPurpose) {
        UpdateCredentialStatusRequest.CredentialStatusDto statusDto = new UpdateCredentialStatusRequest.CredentialStatusDto();
        statusDto.setId(statusListCredential + "#87823");
        statusDto.setType("BitstringStatusListEntry");
        statusDto.setStatusPurpose(statusPurpose);
        statusDto.setStatusListIndex(87823L);
        statusDto.setStatusListCredential(statusListCredential);

        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        request.setCredentialStatus(statusDto);
        request.setStatus(true);
        return request;
    }

    private CredentialStatusTransaction createSavedTransaction(String statusListCredentialId) {
        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setStatusPurpose("revocation");
        transaction.setStatusValue(true);
        transaction.setStatusListCredentialId(statusListCredentialId);
        transaction.setStatusListIndex(87823L);
        transaction.setCreatedDtimes(LocalDateTime.parse("2025-06-11T11:41:30.236"));
        return transaction;
    }

    private StatusListCredential createStatusListCredential(String statusListCredentialId, String statusPurpose) {
        StatusListCredential statusListCredential = new StatusListCredential();
        statusListCredential.setId(statusListCredentialId);
        statusListCredential.setStatusPurpose(statusPurpose);
        return statusListCredential;
    }
}