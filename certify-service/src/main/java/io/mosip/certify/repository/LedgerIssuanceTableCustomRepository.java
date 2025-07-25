package io.mosip.certify.repository;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.entity.Ledger;

import java.util.List;

public interface LedgerIssuanceTableCustomRepository {
    List<Ledger> findBySearchRequest(CredentialLedgerSearchRequest request);
}