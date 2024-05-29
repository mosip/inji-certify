package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;

import java.util.Map;

public interface VCIssuanceService {

    /**
     *
     * @param credentialRequest
     * @return
     */
    <T> CredentialResponse<T> getCredential(CredentialRequest credentialRequest);

    Map<String, Object> getCredentialIssuerMetadata(String version);
}
