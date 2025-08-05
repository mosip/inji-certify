package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;

import java.util.List;

public interface CredentialStatusService {

    CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest updateCredentialStatusRequest);
}
