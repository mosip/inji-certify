package io.mosip.certify.core.spi;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.dto.*;

public interface CredentialConfigurationService {

    CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException;

    CredentialConfigurationDTO getCredentialConfigurationById(String id);

    CredentialConfigResponse updateCredentialConfiguration(String id, CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException;

    String deleteCredentialConfigurationById(String id);

    CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata();
}