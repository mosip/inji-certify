package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.repository.LedgerRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Component
public class CredentialLedgerServiceImpl implements CredentialLedgerService {
    @Autowired
    private LedgerRepository ledgerRepository;

    @Override
    public List<CredentialStatusResponse> searchCredentialLedger(CredentialLedgerSearchRequest request) {
        validateSearchRequest(request);
        try {
            return mapRecordsToResponses(request, false);
        } catch (Exception e) {
            throw new CertifyException("SEARCH_CREDENTIALS_FAILED");
        }
    }

    private CredentialStatusResponse mapToSearchResponse(Ledger record, CredentialStatusDetail statusDetail) {
        CredentialStatusResponse response = new CredentialStatusResponse();
        response.setCredentialId(record.getCredentialId());
        response.setIssuerId(record.getIssuerId());
        response.setIssueDate(record.getIssuanceDate());
        response.setIssuanceDate(record.getIssuanceDate());
        response.setExpirationDate(record.getExpirationDate());
        response.setCredentialType(record.getCredentialType());
        if (statusDetail != null) {
            response.setStatusListCredentialUrl(statusDetail.getStatusListCredentialId());
            response.setStatusListIndex(statusDetail.getStatusListIndex());
            response.setStatusPurpose(statusDetail.getStatusPurpose());
            Long createdDtimes = statusDetail.getCreatedTimes();
            if (createdDtimes != null) {
                LocalDateTime ts = LocalDateTime.ofInstant(
                        Instant.ofEpochMilli(createdDtimes),
                        ZoneOffset.UTC);
                response.setStatusTimestamp(ts);
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

    @Override
    public List<CredentialStatusResponse> searchCredentialLedgerV2(CredentialLedgerSearchRequest request) {
        validateSearchRequest(request);
        try {
            return mapRecordsToResponses(request, true);

        } catch (Exception e) {
            throw new CertifyException("SEARCH_CREDENTIALS_FAILED");
        }
    }

    @Transactional
    @Override
    public void storeLedgerEntry(String credentialId, String issuerId, String credentialType, CredentialStatusDetail statusDetails, Map<String, Object> indexedAttributes, LocalDateTime issuanceDate) {
        try {
            Ledger ledger = new Ledger();
            if(credentialId != null) {
                ledger.setCredentialId(credentialId);
            }
            ledger.setIssuerId(issuerId);
            ledger.setIssuanceDate(issuanceDate);
            ledger.setCredentialType(credentialType);
            ledger.setIndexedAttributes(indexedAttributes);

            // Store status details as array
            List<CredentialStatusDetail> statusDetailsList = new ArrayList<>();
            if(statusDetails != null) {
                statusDetailsList.add(statusDetails);
            }
            ledger.setCredentialStatusDetails(statusDetailsList);

            ledgerRepository.save(ledger);
        } catch (Exception e) {
            log.error("Error storing ledger entry", e);
            throw new RuntimeException("Failed to store ledger entry", e);
        }
    }

    private List<CredentialStatusResponse> mapRecordsToResponses(CredentialLedgerSearchRequest request, boolean isV2) {
        List<Ledger> records = ledgerRepository.findBySearchRequest(request);

        if (records.isEmpty()) {
            return Collections.emptyList();
        }
        return records.stream()
                .flatMap(record -> {
                    List<CredentialStatusDetail> details = record.getCredentialStatusDetails();
                    return Optional.ofNullable(details)
                            .filter(list -> !list.isEmpty())
                            .map(list -> list.stream().map(detail -> {
                                CredentialStatusResponse response = mapToSearchResponse(record, detail);
                                if (isV2) {
                                    response.setIssueDate(null);
                                } else {
                                    response.setIssuanceDate(null);
                                }
                                return response;
                            }))
                            .orElseGet(() -> {
                                CredentialStatusResponse response = mapToSearchResponse(record, null);
                                if (isV2) {
                                    response.setIssueDate(null);
                                } else {
                                    response.setIssuanceDate(null);
                                }
                                return Stream.of(response);
                            });
                })
                .collect(Collectors.toList());
    }

}
