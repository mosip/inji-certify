package io.mosip.certify.core.spi;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.dto.CredentialConfigResponse;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;

public interface CredentialConfigurationService {

    CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException;

    CredentialConfigurationDTO getCredentialConfigurationById(String id) throws JsonProcessingException;

    CredentialConfigResponse updateCredentialConfiguration(String id, CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException;

    String deleteCredentialConfigurationById(String id);

    CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata(String version);
}
