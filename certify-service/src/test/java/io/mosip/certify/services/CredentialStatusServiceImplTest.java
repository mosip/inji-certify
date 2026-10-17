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
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
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
        // mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes={'revocation'}
        ReflectionTestUtils.setField(credentialStatusService, "allowedStatusPurposes", List.of("revocation"));
    }

    @Test
    public void updateCredentialStatusV2_StatusIdMismatch_ThrowsException() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setId("https://example.com/status-list/abc#12345"); // Mismatched ID

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_id_mismatch", exception.getErrorCode());
        assertEquals("Mismatch between credential status ID and Status List Credential.", exception.getMessage());
    }

    @Test
    public void updateCredentialStatusV2_StatusListNotFound_ThrowsException() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.empty());

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: " + statusListCredential, exception.getMessage());
    }

    @Test
    public void should_throwStatusPurposeRequired_when_purposeNullAndConfigured() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose(null); // Null status purpose

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation"); // not a fallback: the feature is enabled, so the client must say
        mockStatusListCredential.setCapacityInKB(1024L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialStatusService.updateCredentialStatus(request));

        assertEquals("status_purpose_required", exception.getErrorCode());
        assertEquals("statusPurpose is required. Allowed values are: [revocation]", exception.getMessage());

        // Nothing may be persisted for a rejected update.
        verify(credentialStatusTransactionRepository, never()).save(any(CredentialStatusTransaction.class));
    }

    @Test
    public void updateCredentialStatusV2_ValidRequest_ReturnsResponse() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");
        mockStatusListCredential.setCapacityInKB(1024L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals(statusListCredential, response.getStatusListCredentialUrl());
        assertEquals("revocation", response.getStatusPurpose());
        assertEquals(87823L, response.getStatusListIndex());
    }

    @Test
    public void updateCredentialStatusV2_NullStatusListCredential_ThrowsException() {
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(null); // Null StatusListCredential

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: null", exception.getMessage());
    }

    @Test
    public void should_throwStatusPurposeRequired_when_purposeEmptyAndConfigured() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose(""); // Empty StatusPurpose

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");
        mockStatusListCredential.setCapacityInKB(1024L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialStatusService.updateCredentialStatus(request));

        assertEquals("status_purpose_required", exception.getErrorCode());
    }

    @Test
    public void updateCredentialStatusV2_InvalidStatusListCredentialFormat_ThrowsException() {
        String statusListCredential = "invalid-format";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: invalid-format", exception.getMessage());
    }

    @Test
    public void should_throwInvalidStatusPurposeExceptionException_when_statusPurposeIsInvalid() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose("invalid_purpose"); // Invalid status purpose

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setStatusPurpose("revocation");
        mockStatusListCredential.setCapacityInKB(1024L); // 1MB capacity

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("invalid_status_purpose", exception.getErrorCode());
        assertEquals("Invalid status purpose 'invalid_purpose'. Allowed values are: [revocation]", exception.getMessage());
    }

    @Test
    public void should_throwInvalidStatusPurposeExceptionException_when_statusPurposeNotConfigured_evenIfStoredOnStatusList() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose("suspension"); // not in the configured allowed list

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setStatusPurpose("suspension"); // matches the stored list, which is not the reference
        mockStatusListCredential.setCapacityInKB(1024L); // 1MB capacity

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("invalid_status_purpose", exception.getErrorCode());
        assertEquals("Invalid status purpose 'suspension'. Allowed values are: [revocation]", exception.getMessage());
    }

    @Test
    public void should_acceptConfiguredStatusPurpose_when_statusListStoresNoPurpose() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose("revocation");

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setStatusPurpose(null); // would have been a mismatch against the stored list
        mockStatusListCredential.setCapacityInKB(1024L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertEquals("revocation", response.getStatusPurpose());
    }

    @Test
    public void should_fallBackToStatusListPurpose_when_purposeOmittedAndPropertyUnset() {
        // Property unset means the revocation feature is not enabled, so an issuer that sends no
        // purpose is simply not using it: accepted, and recorded against the list's own purpose.
        ReflectionTestUtils.setField(credentialStatusService, "allowedStatusPurposes", List.of());
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose(null);

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setStatusPurpose("suspension");
        mockStatusListCredential.setCapacityInKB(1024L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals("suspension", response.getStatusPurpose());

        ArgumentCaptor<CredentialStatusTransaction> saved = ArgumentCaptor.forClass(CredentialStatusTransaction.class);
        verify(credentialStatusTransactionRepository).save(saved.capture());
        assertEquals("suspension", saved.getValue().getStatusPurpose());
    }

    @Test
    public void should_acceptPaddedStatusPurpose_when_trimmedValueIsConfigured() {
        // The same trim that makes "   " count as not-given also makes " revocation " match,
        // so padding never changes the outcome.
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose("  revocation  ");

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setStatusPurpose("revocation");
        mockStatusListCredential.setCapacityInKB(1024L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals("revocation", response.getStatusPurpose());
    }

    @Test
    public void should_throwInvalidStatusPurposeException_when_submittedPurposeDiffersExistingPurposeInStatusListCredential() {
        // The purpose matches with configured value(s) but the new value is different to the DB stored prupose for the 
        // status_list_credential
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose("revocation");

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setStatusPurpose("suspension");
        mockStatusListCredential.setCapacityInKB(1024L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        // CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialStatusService.updateCredentialStatus(request));

        assertEquals("invalid_status_purpose", exception.getErrorCode());
        assertEquals("Status purpose 'revocation' does not match the status list purpose 'suspension'", exception.getMessage());
    }

    @Test
    public void should_ignoreRequestedPurpose_when_propertyUnset() {
        // Nothing configured means the feature is not enabled, so the requested purpose is not
        // acted on at all: the purpose recorded against the status list is kept as it was.
        ReflectionTestUtils.setField(credentialStatusService, "allowedStatusPurposes", List.of());
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose("suspension"); // ignored, not validated

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setStatusPurpose("revocation"); // the purpose that must survive
        mockStatusListCredential.setCapacityInKB(1024L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals("revocation", response.getStatusPurpose());

        // The requested purpose must not reach the stored row.
        ArgumentCaptor<CredentialStatusTransaction> saved = ArgumentCaptor.forClass(CredentialStatusTransaction.class);
        verify(credentialStatusTransactionRepository).save(saved.capture());
        assertEquals("revocation", saved.getValue().getStatusPurpose());
    }

    @Test
    public void should_throwInvalidRequest_when_statusListIndexIsNull() {
        // Reachable only by calling the service directly: over HTTP, @Valid rejects a null
        // index first. Without the guard this was a NullPointerException from auto-unboxing.
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusListIndex(null);

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");
        mockStatusListCredential.setCapacityInKB(1024L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("invalid_request", exception.getErrorCode());
        assertEquals("statusListIndex is required", exception.getMessage());
    }

    @Test
    public void should_throwIndexOutOfBoundsException_when_statusListIndexIsNegative() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusListIndex(-1L); // Negative index

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");
        mockStatusListCredential.setCapacityInKB(1024L); // 1MB capacity

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("requested_index_is_out_of_bounds_for_status_list_capacity", exception.getErrorCode());
        assertEquals("statusListIndex must be non-negative, received: -1", exception.getMessage());
    }

    @Test
    public void should_throwIndexOutOfBoundsException_when_statusListIndexExceedsCapacity() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        // Set capacity to 20KB (above 16KB minimum)
        // 20KB = 20 * 1024 * 8 = 163840 bits (max index is 163839)
        long capacityInKB = 20L;
        long maxCapacity = capacityInKB * 1024L * 8L; // 163840
        request.getCredentialStatus().setStatusListIndex(maxCapacity + 100); // 163940 (exceeds capacity)

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");
        mockStatusListCredential.setCapacityInKB(capacityInKB);
        mockStatusListCredential.setId(statusListCredential);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("requested_index_is_out_of_bounds_for_status_list_capacity", exception.getErrorCode());
        assertEquals("statusListIndex " + (maxCapacity + 100) + " exceeds maximum capacity " +
                maxCapacity + " for status list '" + statusListCredential + "'", exception.getMessage());
    }

    @Test
    public void should_throwIndexOutOfBoundsException_when_statusListIndexIsAtMaxCapacityBoundary() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        // Set capacity to 20KB (above 16KB minimum)
        // 20KB = 20 * 1024 * 8 = 163840 bits (max index is 163839)
        long capacityInKB = 20L;
        long maxCapacity = capacityInKB * 1024L * 8L; // 163840
        request.getCredentialStatus().setStatusListIndex(maxCapacity); // 163840 (exactly at boundary, should fail)

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");
        mockStatusListCredential.setCapacityInKB(capacityInKB);
        mockStatusListCredential.setId(statusListCredential);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("requested_index_is_out_of_bounds_for_status_list_capacity", exception.getErrorCode());
        assertEquals("statusListIndex " + maxCapacity + " exceeds maximum capacity " +
                maxCapacity + " for status list '" + statusListCredential + "'", exception.getMessage());
    }

    @Test
    public void should_updateCredentialStatusSuccessfully_when_statusListIndexIsAtMaxValidBoundary() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        // Set capacity to 20KB (above 16KB minimum)
        // 20KB = 20 * 1024 * 8 = 163840 bits (max valid index is 163839)
        long capacityInKB = 20L;
        long maxCapacity = capacityInKB * 1024L * 8L; // 163840
        request.getCredentialStatus().setStatusListIndex(maxCapacity - 1); // 163839 (valid boundary)

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");
        mockStatusListCredential.setCapacityInKB(capacityInKB);
        mockStatusListCredential.setId(statusListCredential);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals(maxCapacity - 1, response.getStatusListIndex());
        assertEquals("revocation", response.getStatusPurpose());
    }

    private UpdateCredentialStatusRequest createValidUpdateCredentialRequest(String statusListCredential) {
        UpdateCredentialStatusRequest.CredentialStatusDto statusDto = new UpdateCredentialStatusRequest.CredentialStatusDto();
        statusDto.setId(statusListCredential);
        statusDto.setType("BitstringStatusListEntry");
        statusDto.setStatusPurpose("revocation");
        statusDto.setStatusListIndex(87823L);
        statusDto.setStatusListCredential(statusListCredential);

        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        request.setCredentialStatus(statusDto);
        request.setStatus(true); // Mark as revoked

        return request;
    }
    
    @Test
    public void should_throwStatusPurposeRequired_when_purposeIsWhitespaceOnly() {
        // Whitespace-only is trimmed to nothing, so it counts as "not given" exactly like ""
        // and null do. One trim, one value: a client cannot get a different error by padding.
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose("   ");

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setCapacityInKB(20L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_purpose_required", exception.getErrorCode());
    }

    @Test
    public void should_throwInvalidStatusPurposeExceptionException_when_statusPurposeDiffersOnlyByCase() {
        // The configured list is documented as case-sensitive, so a capitalised variant is not a match.
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose("Revocation");

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setCapacityInKB(20L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialStatusService.updateCredentialStatus(request));

        assertEquals("invalid_status_purpose", exception.getErrorCode());
        assertEquals("Invalid status purpose 'Revocation'. Allowed values are: [revocation]", exception.getMessage());
    }

    @Test
    public void should_acceptAnyConfiguredStatusPurpose_when_deploymentAllowsSeveral() {
        // Proves the check reads the configured list rather than a single hard-coded purpose.
        ReflectionTestUtils.setField(credentialStatusService, "allowedStatusPurposes", List.of("revocation", "suspension"));
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose("suspension");

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setCapacityInKB(20L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertEquals("suspension", response.getStatusPurpose());
    }


    @Test
    public void should_updateCredentialStatusSuccessfully_when_statusListIndexIsZero() {
        // Zero is the first valid index; the lower bound rejects negatives only.
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusListIndex(0L);

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setCapacityInKB(20L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertEquals(Long.valueOf(0L), response.getStatusListIndex());
    }

    @Test
    public void should_boundIndexByMinimumCapacity_when_statusListIsConfiguredBelowTheFloor() {
        // A list configured below 16 KB is still built at the 131072-bit floor, so an index inside
        // the floor addresses a real bit and must be accepted. 1 KB alone would be only 8192 bits.
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusListIndex(100000L);

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setCapacityInKB(1L);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertEquals(Long.valueOf(100000L), response.getStatusListIndex());
    }

    @Test
    public void should_throwCapacityMisconfigured_when_statusListHasNoCapacity() {
        // A status list stored without a capacity has no range to validate against.
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setId(statusListCredential);
        mockStatusListCredential.setCapacityInKB(null);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialStatusService.updateCredentialStatus(request));

        assertEquals("status_list_capacity_misconfigured", exception.getErrorCode());
    }
}
