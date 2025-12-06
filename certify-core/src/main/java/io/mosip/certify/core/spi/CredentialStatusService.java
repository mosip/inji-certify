package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequestV2;

public interface CredentialStatusService {

    CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest updateCredentialStatusRequest);

    CredentialStatusResponse updateCredentialStatusV2(UpdateCredentialStatusRequestV2 updateCredentialStatusRequestV2);
}
