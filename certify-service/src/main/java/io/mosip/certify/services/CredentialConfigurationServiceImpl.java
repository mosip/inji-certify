package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.TemplateId;
import io.mosip.certify.mapper.CredentialConfigMapper;
import io.mosip.certify.repository.CredentialConfigRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.util.*;

@Slf4j
@Component
@Transactional
public class CredentialConfigurationServiceImpl implements CredentialConfigurationService {

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private CredentialConfigMapper credentialConfigMapper;

    @Value("${mosip.certify.identifier}")
    private String credentialIssuer;

    @Value("#{'${mosip.certify.authorization.url}'.split(',')}")
    private List<String> authServers;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.plugin-mode}")
    private String pluginMode;

    @Value("#{${mosip.certify.credential-config.issuer.display}}")
    private List<Map<String, String>> issuerDisplay;

    @Override
    public CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException {
        CredentialConfig credentialConfig = credentialConfigMapper.toEntity(credentialConfigurationDTO);
        TemplateId templateId = new TemplateId();
        templateId.setCredentialType(credentialConfig.getCredentialType());
        templateId.setContext(credentialConfig.getContext());
        templateId.setCredentialFormat(credentialConfig.getCredentialFormat());

        Optional<CredentialConfig> optional = credentialConfigRepository.findById(templateId);

        if(optional.isPresent()) {
            throw new CertifyException("Credential type already exists. Try updating the credential.");
        }

        credentialConfig.setConfigId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);

        if(pluginMode.equals("DataProvider") && credentialConfig.getVcTemplate() == null) {
            throw new CertifyException("Credential Template is mandatory for this `DataProvider` plugin issuer.");
        }

        if(credentialConfig.getCredentialFormat().equals("mso_mdoc")) {
            if(credentialConfigurationDTO.getClaims() == null || credentialConfigurationDTO.getDocType() == null) {
                throw new CertifyException("Claims and Doctype fields are mandatory for this credential format.");
            }
        } else if(credentialConfig.getCredentialSubject() == null) {
            throw new CertifyException("Credential Subject field is mandatory for this credential format.");
        }

        credentialConfigRepository.save(credentialConfig);

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(credentialConfig.getConfigId());
        credentialConfigResponse.setStatus(credentialConfig.getStatus());

        return credentialConfigResponse;
    }

    @Override
    public CredentialConfigurationDTO getCredentialConfigurationById(String id) throws JsonProcessingException {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByConfigId(id);

        if(optional.isEmpty()) {
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        CredentialConfig credentialConfig = optional.get();
        if(!credentialConfig.getStatus().equals(Constants.ACTIVE)) {
            throw new CertifyException("Configuration not active.");
        }

        CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);

        return credentialConfigurationDTO;
    }

    @Override
    public CredentialConfigResponse updateCredentialConfiguration(String id, CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByConfigId(id);

        if(optional.isEmpty()) {
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        CredentialConfig credentialConfig = optional.get();
        credentialConfigMapper.updateEntityFromDto(credentialConfigurationDTO, credentialConfig);
        credentialConfigRepository.save(credentialConfig);

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(credentialConfig.getConfigId());
        credentialConfigResponse.setStatus(credentialConfig.getStatus());

        return credentialConfigResponse;
    }

    @Override
    public String deleteCredentialConfigurationById(String id) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByConfigId(id);

        if(optional.isEmpty()) {
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        credentialConfigRepository.delete(optional.get());
        return "Configuration deleted with id: " + id;
    }

    @Override
    public CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata(String version) {
        CredentialIssuerMetadataDTO credentialIssuerMetadata = new CredentialIssuerMetadataDTO();
        credentialIssuerMetadata.setCredentialIssuer(credentialIssuer);
        credentialIssuerMetadata.setAuthorizationServers(authServers);
        String credentialEndpoint = credentialIssuer + servletPath + "/issuance" + (!version.equals("latest") ? "/" +version : "") + "/credential" ;
        credentialIssuerMetadata.setCredentialEndpoint(credentialEndpoint);
        credentialIssuerMetadata.setDisplay(issuerDisplay);
        List<CredentialConfig> credentialConfigList = credentialConfigRepository.findAll();
        Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();
        credentialConfigList.stream()
                .forEach(credentialConfig -> {
                    CredentialConfigurationSupportedDTO credentialConfigurationSupported = new CredentialConfigurationSupportedDTO();
                    CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);
                    credentialConfigurationSupported.setFormat(credentialConfigurationDTO.getCredentialFormat());
                    credentialConfigurationSupported.setScope(credentialConfigurationDTO.getScope());
                    credentialConfigurationSupported.setCryptographicBindingMethodsSupported(credentialConfigurationDTO.getCryptographicBindingMethodsSupported());
                    credentialConfigurationSupported.setCredentialSigningAlgValuesSupported(credentialConfigurationDTO.getCredentialSigningAlgValuesSupported());
                    credentialConfigurationSupported.setProofTypesSupported(credentialConfigurationDTO.getProofTypesSupported());

                    credentialConfigurationSupported.setDisplay(credentialConfigurationDTO.getDisplay());
                    credentialConfigurationSupported.setOrder(credentialConfigurationDTO.getOrder());

                    if(credentialConfig.getCredentialSubject() != null) {
                        CredentialDefinition credentialDefinition = new CredentialDefinition();
                        credentialDefinition.setType(credentialConfigurationDTO.getCredentialType());
                        credentialDefinition.setContext(credentialConfigurationDTO.getContext());
                        credentialDefinition.setCredentialSubject(credentialConfig.getCredentialSubject());
                        credentialConfigurationSupported.setCredentialDefinition(credentialDefinition);
                    } else {
                        credentialConfigurationSupported.setClaims(credentialConfig.getClaims());
                        credentialConfigurationSupported.setDocType(credentialConfig.getDocType());
                    }

                    credentialConfigurationSupportedMap.put(credentialConfigurationDTO.getCredentialConfigKeyId(), credentialConfigurationSupported);
                });

        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap);
        return credentialIssuerMetadata;
    }
}
