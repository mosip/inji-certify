package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusResponse;

import java.util.List;

public interface CredentialLedgerService {
    List<CredentialStatusResponse> searchCredentialLedger(CredentialLedgerSearchRequest request);
    List<CredentialStatusResponse> searchCredentialLedgerV2(CredentialLedgerSearchRequest request);
}
