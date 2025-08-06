package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.repository.LedgerRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Component
public class CredentialLedgerServiceImpl implements CredentialLedgerService {
    @Autowired
    private LedgerRepository ledgerRepository;

    @Override
    public List<CredentialStatusResponse> searchCredentialLedger(CredentialLedgerSearchRequest request) {
        validateSearchRequest(request);
        try {
            List<Ledger> records = ledgerRepository.findBySearchRequest(request);

            if (records.isEmpty()) {
                return Collections.emptyList();
            }

            return records.stream()
                    .map(this::mapToSearchResponse)
                    .collect(Collectors.toList());

        } catch (Exception e) {
            throw new CertifyException("SEARCH_CREDENTIALS_FAILED");
        }
    }

    private CredentialStatusResponse mapToSearchResponse(Ledger record) {
        CredentialStatusResponse response = new CredentialStatusResponse();
        response.setCredentialId(record.getCredentialId());
        response.setIssuerId(record.getIssuerId());
        response.setIssueDate(record.getIssueDate().toLocalDateTime());
        response.setExpirationDate(record.getExpirationDate() != null ? record.getExpirationDate().toLocalDateTime() : null);
        response.setCredentialType(record.getCredentialType());
        List<Map<String, Object>> statusDetails = record.getCredentialStatusDetails();
        if (statusDetails != null && !statusDetails.isEmpty()) {
            Map<String, Object> latestStatus = statusDetails.get(0);
            Object statusListCredentialId = latestStatus.get("status_list_credential_id");
            Object statusListIndex = latestStatus.get("status_list_index");
            Object statusPurpose = latestStatus.get("status_purpose");
            Object createdDtimes = latestStatus.get("cr_dtimes");

            if (statusListCredentialId != null) {
                response.setStatusListCredentialUrl(statusListCredentialId.toString());
            }

            if (statusListIndex instanceof Number) {
                Long index = ((Number) statusListIndex).longValue();
                response.setStatusListIndex(index);
            }

            if (statusPurpose != null) {
                response.setStatusPurpose(statusPurpose.toString());
            }

            if (createdDtimes instanceof Number) {
                long timestampMillis = ((Number) createdDtimes).longValue();
                OffsetDateTime createdDateTime = OffsetDateTime.ofInstant(
                        java.time.Instant.ofEpochMilli(timestampMillis),
                        java.time.ZoneOffset.UTC
                );
                response.setStatusTimestamp(createdDateTime.toLocalDateTime());
            }
        }
        return response;
    }

    private void validateSearchRequest(CredentialLedgerSearchRequest request) {
        Map<String, String> indexedAttrs = request.getIndexedAttributesEquals();

        boolean hasValid = indexedAttrs != null && !indexedAttrs.isEmpty() &&
                indexedAttrs.entrySet().stream()
                        .anyMatch(e -> e.getKey() != null && !e.getKey().isBlank()
                                && e.getValue() != null && !e.getValue().isBlank());

        if (!hasValid) {
            throw new CertifyException("INVALID_SEARCH_CRITERIA");
        }
    }
}
