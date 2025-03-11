package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialConfigurationRequest;

import java.util.Map;

public interface CredentialConfigurationService {

    Map<String, String> addCredentialConfiguration(CredentialConfigurationRequest credentialConfigurationRequest);

    CredentialConfigurationRequest getCredentialConfigurationById(String id);

    Map<String, String> updateCredentialConfiguration(String id, CredentialConfigurationRequest credentialConfigurationRequest);

    void deleteCredentialConfigurationById(String id);
}
