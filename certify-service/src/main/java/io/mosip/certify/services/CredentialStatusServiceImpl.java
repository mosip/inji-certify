package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.BitStringStatusListUtils;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CredentialStatusServiceImpl implements CredentialStatusService {
    private final CredentialStatusTransactionRepository credentialStatusTransactionRepository;

    private final StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    public CredentialStatusServiceImpl(CredentialStatusTransactionRepository credentialStatusTransactionRepository,
                                       StatusListCredentialRepository statusListCredentialRepository) {
        this.credentialStatusTransactionRepository = credentialStatusTransactionRepository;
        this.statusListCredentialRepository = statusListCredentialRepository;
    }

    /** Status purposes a deployment allows; the first entry is the default when a request omits it. */
    @Value("#{${mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes:{}}}")
    private List<String> allowedStatusPurposes;

    @Override
    public CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest request) {
        String statusListCredentialId = request.getCredentialStatus().getStatusListCredential();
        Long statusListIndex = request.getCredentialStatus().getStatusListIndex();
        String id = request.getCredentialStatus().getId();

        if(id != null && !id.equals(statusListCredentialId)) {
            throw new CertifyException(ErrorConstants.STATUS_ID_MISMATCH, "Mismatch between credential status ID and Status List Credential.");
        }
        StatusListCredential statusListCredential = statusListCredentialRepository.findById(statusListCredentialId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND, "Status List Credential not found for ID: " + statusListCredentialId));

        validateStatusListIndex(statusListIndex, statusListCredential);
        String validatedPurpose = resolveStatusPurpose(request.getCredentialStatus().getStatusPurpose(),
                statusListCredential);

        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setStatusPurpose(validatedPurpose);
        transaction.setStatusValue(request.getStatus());
        transaction.setStatusListCredentialId(statusListCredentialId);
        transaction.setStatusListIndex(statusListIndex);
        CredentialStatusTransaction savedTransaction =credentialStatusTransactionRepository.save(transaction);

        CredentialStatusResponse dto = new CredentialStatusResponse();
        dto.setStatusListCredentialUrl(transaction.getStatusListCredentialId());
        dto.setStatusListIndex(transaction.getStatusListIndex());
        dto.setStatusPurpose(transaction.getStatusPurpose());
        dto.setStatusTimestamp(savedTransaction.getCreatedDtimes());
        if(request.getCredentialStatus().getType() != null) {
            dto.setCredentialType(request.getCredentialStatus().getType());
        }
        return dto;
    }

    /**
     * Validates the requested index against the referenced status list's capacity.
     */
    private void validateStatusListIndex(Long statusListIndex, StatusListCredential statusListCredential) {
        if (statusListIndex == null) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "statusListIndex is required");
        }

        if (statusListIndex < 0) {
            throw new CertifyException(ErrorConstants.INDEX_OUT_OF_BOUNDS,
                "statusListIndex must be non-negative, received: " + statusListIndex);
        }

        long maxCapacity = BitStringStatusListUtils.safeConvertKBToBits(statusListCredential.getCapacityInKB());

        if (statusListIndex >= maxCapacity) {
            throw new CertifyException(ErrorConstants.INDEX_OUT_OF_BOUNDS,
                "statusListIndex " + statusListIndex + " exceeds maximum capacity " +
                maxCapacity + " for status list '" + statusListCredential.getId() + "'");
        }
    }

    /**
     * Resolves the status purpose to store for this update. It can only change if given and the allowed purposes are
     * given from the app properties
     */
    private String resolveStatusPurpose(String requestedPurpose, StatusListCredential statusListCredential) {
        String statusListPurpose = statusListCredential.getStatusPurpose();
        if (allowedStatusPurposes == null || allowedStatusPurposes.isEmpty()) {
            // The feature is not enabled, so leave the recorded purpose as it is.
            return statusListPurpose;
        }

        // Trimmed once here and used everywhere below
        String purpose = StringUtils.trimToNull(requestedPurpose);

        if (purpose == null) {
            throw new CertifyException(ErrorConstants.STATUS_PURPOSE_REQUIRED,
                "statusPurpose is required. Allowed values are: " + allowedStatusPurposes);
        }

        if (!allowedStatusPurposes.contains(purpose)) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE,
                "Invalid status purpose '" + purpose + "'. Allowed values are: " + allowedStatusPurposes);
        }
        
        if(statusListPurpose !=null && !statusListPurpose.isEmpty() && !statusListPurpose.equals(purpose)){
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE,
                "Status purpose '" + purpose + "' does not match the status list purpose '" + statusListPurpose + "'");
        }
        return purpose;
    }
}
