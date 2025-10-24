package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public interface CredentialLedgerService {
    List<CredentialStatusResponse> searchCredentialLedger(CredentialLedgerSearchRequest request);
    List<CredentialStatusResponse> searchCredentialLedgerV2(CredentialLedgerSearchRequest request);
    void storeLedgerEntry(String credentialId, String issuerId, String credentialType, CredentialStatusDetail statusDetails, Map<String, Object> indexedAttributes, LocalDateTime issuanceDate);
}
