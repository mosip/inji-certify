package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequestV2;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.entity.attributes.CredentialStatusDetail;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
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

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Value("#{${mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes:{}}}")
    private List<String> allowedCredentialStatusPurposes;

    @Override
    public CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest request) {

        if (request.getCredentialStatus().getStatusPurpose() != null && !allowedCredentialStatusPurposes.contains(request.getCredentialStatus().getStatusPurpose())) {
            throw new CertifyException("Invalid credential status purpose. Allowed values are: " + allowedCredentialStatusPurposes);
        }
        Ledger ledger = ledgerRepository.findByCredentialId(request.getCredentialId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Credential not found: " + request.getCredentialId()));

        if(ledger.getCredentialStatusDetails() == null || ledger.getCredentialStatusDetails().isEmpty()) {
            throw new CertifyException("CredentialStatus details are not present in the issued credential.");
        }

        CredentialStatusDetail credentialStatusDetail = ledger.getCredentialStatusDetails().getFirst();
        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setCredentialId(ledger.getCredentialId());
        transaction.setStatusPurpose(credentialStatusDetail.getStatusPurpose());
        transaction.setStatusValue(request.getStatus());
        transaction.setStatusListCredentialId(credentialStatusDetail.getStatusListCredentialId());
        transaction.setStatusListIndex(credentialStatusDetail.getStatusListIndex());
        CredentialStatusTransaction savedTransaction =credentialStatusTransactionRepository.save(transaction);

        CredentialStatusResponse dto = new CredentialStatusResponse();
        dto.setCredentialId(ledger.getCredentialId());
        dto.setIssuerId(ledger.getIssuerId());
        dto.setCredentialType(ledger.getCredentialType());
        dto.setIssueDate(ledger.getIssuanceDate());
        dto.setExpirationDate(ledger.getExpirationDate());
        dto.setStatusListCredentialUrl(credentialStatusDetail.getStatusListCredentialId());
        dto.setStatusListIndex(credentialStatusDetail.getStatusListIndex());
        dto.setStatusPurpose(credentialStatusDetail.getStatusPurpose());
        dto.setStatusTimestamp(savedTransaction.getCreatedDtimes());
        return dto;
    }

    @Override
    public CredentialStatusResponse updateCredentialStatusV2(UpdateCredentialStatusRequestV2 request) {
        if (request.getCredentialStatus().getStatusPurpose() != null && !allowedCredentialStatusPurposes.contains(request.getCredentialStatus().getStatusPurpose())) {
            throw new CertifyException("Invalid credential status purpose. Allowed values are: " + allowedCredentialStatusPurposes);
        }
        String statusListCredentialId = request.getCredentialStatus().getStatusListCredential();
        Long statusListIndex = request.getCredentialStatus().getStatusListIndex();
        StatusListCredential statusListCredential = statusListCredentialRepository.findById(statusListCredentialId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "StatusListCredential not found with id: " + statusListCredentialId));

        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setStatusPurpose(statusListCredential.getStatusPurpose());
        transaction.setStatusValue(request.getStatus());
        transaction.setStatusListCredentialId(statusListCredentialId);
        transaction.setStatusListIndex(statusListIndex);
        CredentialStatusTransaction savedTransaction =credentialStatusTransactionRepository.save(transaction);

        CredentialStatusResponse dto = new CredentialStatusResponse();
        dto.setStatusListCredentialUrl(transaction.getStatusListCredentialId());
        dto.setStatusListIndex(transaction.getStatusListIndex());
        dto.setStatusPurpose(transaction.getStatusPurpose());
        dto.setStatusTimestamp(savedTransaction.getCreatedDtimes());
        return dto;
    }
}
