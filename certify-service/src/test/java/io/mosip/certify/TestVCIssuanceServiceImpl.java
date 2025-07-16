package io.mosip.certify;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.VCIssuanceService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.util.Map;
import java.util.Collections;
import java.util.List;

@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "VCIssuance")
public class TestVCIssuanceServiceImpl implements VCIssuanceService {
    @Override
    public <T> CredentialResponse<T> getCredential(CredentialRequest credentialRequest) {
        CredentialResponse<T> credentialResponse = new CredentialResponse<>();
        credentialResponse.setCredential((T) "Mock Credential");
        credentialResponse.setFormat("mock-format");
        credentialResponse.setC_nonce("fake-nonce");
        credentialResponse.setAcceptance_token("fake-token");
        credentialResponse.setC_nonce_expires_in(3600);
        return credentialResponse;
    }

    @Override
    public Map<String, Object> getCredentialIssuerMetadata(String version) {
        return Map.of();
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE);
    }

    @Override
    public CredentialStatusResponse updateCredential(UpdateCredentialStatusRequest request) {
        throw new UnsupportedOperationException("updateCredential is not implemented yet");
    }

    @Override
    public List<CredentialStatusResponse> searchCredentials(CredentialLedgerSearchRequest request) {
        return Collections.emptyList();
    }
}
