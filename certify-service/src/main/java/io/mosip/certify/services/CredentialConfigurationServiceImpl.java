package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialConfigResponse;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Component
public class CredentialConfigurationServiceImpl implements CredentialConfigurationService {
    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Override
    public CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException {
        CredentialConfig credentialConfig = new CredentialConfig();
        credentialConfig.setId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);
        String configuration = objectMapper.writeValueAsString(credentialConfigurationDTO);
        credentialConfig.setConfiguration(configuration);
        credentialConfig.setCreatedTime(LocalDateTime.now());
        credentialConfigRepository.save(credentialConfig);

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(credentialConfig.getId());
        credentialConfigResponse.setStatus(credentialConfig.getStatus());

        return credentialConfigResponse;
    }

    @Override
    public CredentialConfigurationDTO getCredentialConfigurationById(String id) throws JsonProcessingException {
        Optional<CredentialConfig> optional = credentialConfigRepository.findById(id);

        if(optional.isEmpty()) {
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        CredentialConfig credentialConfig = optional.get();
        if(!credentialConfig.getStatus().equals(Constants.ACTIVE)) {
            throw new CertifyException("Configuration not active.");
        }

        String configuration = credentialConfig.getConfiguration();
        CredentialConfigurationDTO credentialConfigurationDTO = objectMapper.readValue(configuration, CredentialConfigurationDTO.class);
        return credentialConfigurationDTO;
    }

    @Override
    public CredentialConfigResponse updateCredentialConfiguration(String id, CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException {
        Optional<CredentialConfig> optional = credentialConfigRepository.findById(id);

        if(optional.isEmpty()) {
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        CredentialConfig credentialConfig = optional.get();
        String configuration = objectMapper.writeValueAsString(credentialConfigurationDTO);
        credentialConfig.setConfiguration(configuration);
        credentialConfigRepository.save(credentialConfig);

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(credentialConfig.getId());
        credentialConfigResponse.setStatus(credentialConfig.getStatus());

        return credentialConfigResponse;
    }

    @Override
    public String deleteCredentialConfigurationById(String id) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findById(id);

        if(optional.isEmpty()) {
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        credentialConfigRepository.deleteById(id);
        return "Configuration deleted with id: " + id;
    }
}
