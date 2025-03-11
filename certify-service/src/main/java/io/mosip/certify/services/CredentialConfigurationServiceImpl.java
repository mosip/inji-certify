package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialConfigurationRequest;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class CredentialConfigurationServiceImpl implements CredentialConfigurationService {
    @Override
    public Map<String, String> addCredentialConfiguration(CredentialConfigurationRequest credentialConfigurationRequest) {
        Map<String, String> configurationResponse = new HashMap<>();
        configurationResponse.put("id", "farmer-credential-config-001");
        configurationResponse.put("status", "active");

        return configurationResponse;
    }

    @Override
    public CredentialConfigurationRequest getCredentialConfigurationById(String id) {
        return new CredentialConfigurationRequest();
    }

    @Override
    public Map<String, String> updateCredentialConfiguration(String id, CredentialConfigurationRequest credentialConfigurationRequest) {
        Map<String, String> configurationResponse = new HashMap<>();
        configurationResponse.put("id", "farmer-credential-config-001");
        configurationResponse.put("status", "active");

        return configurationResponse;
    }

    @Override
    public void deleteCredentialConfigurationById(String id) {

    }
}
