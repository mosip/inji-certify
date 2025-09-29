package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.LedgerRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Slf4j
@Service
public class CredentialStatusServiceImpl implements CredentialStatusService {
    @Autowired
    private LedgerRepository ledgerRepository;

    @Autowired
    private CredentialStatusTransactionRepository credentialStatusTransactionRepository;

    @Value("#{${mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes:{}}}")
    private List<String> allowedCredentialStatusPurposes;

    @Override
    public CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest request) {

        if (request.getCredentialStatus().getStatusPurpose() != null && !allowedCredentialStatusPurposes.contains(request.getCredentialStatus().getStatusPurpose())) {
            throw new CertifyException("Invalid credential status purpose. Allowed values are: " + allowedCredentialStatusPurposes);
        }
        String statusListCredentialId = request.getCredentialStatus().getStatusListCredential();
        Long statusListIndex = request.getCredentialStatus().getStatusListIndex();
        Ledger ledger = ledgerRepository.findByStatusListCredentialIdAndStatusListIndex(statusListCredentialId, statusListIndex)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Credential not found with statusListCredentialId: " + statusListCredentialId + " and statusListIndex: " + statusListIndex));

        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setCredentialId(ledger.getCredentialId());
        if(request.getCredentialStatus().getStatusPurpose() == null) {
            transaction.setStatusPurpose(ledger.getCredentialStatusDetails().get(0).getStatusPurpose());
        } else {
            transaction.setStatusPurpose(request.getCredentialStatus().getStatusPurpose());
        }
        transaction.setStatusValue(request.getStatus());
        transaction.setStatusListCredentialId(statusListCredentialId);
        transaction.setStatusListIndex(statusListIndex);
        CredentialStatusTransaction savedTransaction =credentialStatusTransactionRepository.save(transaction);

        CredentialStatusResponse dto = new CredentialStatusResponse();
        dto.setCredentialId(ledger.getCredentialId());
        dto.setIssuerId(ledger.getIssuerId());
        dto.setCredentialType(ledger.getCredentialType());
        dto.setIssueDate(ledger.getIssueDate().toLocalDateTime());
        dto.setExpirationDate(ledger.getExpirationDate() != null ? ledger.getExpirationDate().toLocalDateTime() : null);
        dto.setStatusListCredentialUrl(request.getCredentialStatus().getStatusListCredential());
        dto.setStatusListIndex(request.getCredentialStatus().getStatusListIndex());
        dto.setStatusPurpose(request.getCredentialStatus().getStatusPurpose());
        dto.setStatusTimestamp(savedTransaction.getCreatedDtimes());
        return dto;
    }
}
