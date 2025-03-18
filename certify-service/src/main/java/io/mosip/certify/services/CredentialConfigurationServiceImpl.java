package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.CredentialDisplay;
import io.mosip.certify.mapper.CredentialConfigMapper;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.CredentialDisplayRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Component
@Transactional
public class CredentialConfigurationServiceImpl implements CredentialConfigurationService {

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private CredentialConfigMapper credentialConfigMapper;

    @Autowired
    private CredentialDisplayRepository credentialDisplayRepository;

    @Value("${mosip.certify.identifier}")
    private String credentialIssuer;

    @Value("#{'${mosip.certify.authorization.url}'.split(',')}")
    private List<String> authServers;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Override
    public CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException {
        CredentialConfig credentialConfig = credentialConfigMapper.toEntity(credentialConfigurationDTO);
        credentialConfig.setId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);

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

        CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);

        return credentialConfigurationDTO;
    }

    @Override
    public CredentialConfigResponse updateCredentialConfiguration(String id, CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException {
        Optional<CredentialConfig> optional = credentialConfigRepository.findById(id);

        if(optional.isEmpty()) {
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        CredentialConfig credentialConfig = optional.get();
        credentialConfigMapper.updateEntityFromDto(credentialConfigurationDTO, credentialConfig);
        log.info("credential config: " + credentialConfig.getCredentialType());

        if(credentialConfig.getDisplay() != null && credentialConfigurationDTO.getDisplay() != null) {
            credentialConfigMapper.updateDisplayFromDto(credentialConfigurationDTO.getDisplay(), credentialConfig.getDisplay());
        } else {
            credentialConfig.setDisplay(credentialConfigMapper.toEntity(credentialConfigurationDTO.getDisplay()));
        }

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

    @Override
    public CredentialIssuerMetadata fetchCredentialIssuerMetadata(String version) {
        CredentialIssuerMetadata credentialIssuerMetadata = new CredentialIssuerMetadata();
        credentialIssuerMetadata.setCredentialIssuer(credentialIssuer);
        credentialIssuerMetadata.setAuthorizationServers(authServers);
        String credentialEndpoint = credentialIssuer + servletPath + "/issuance" + (!version.equals("latest") ? "/" +version : "") + "/credential" ;
        credentialIssuerMetadata.setCredentialEndpoint(credentialEndpoint);
//        credentialIssuerMetadata.setDisplay((List<Map<String, String>>) originalIssuerMetadata.get("display"));
        List<CredentialConfig> credentialConfigList = credentialConfigRepository.findAll();
        Map<String, CredentialConfigurationSupported> credentialConfigurationSupportedMap = new HashMap<>();
        credentialConfigList.stream()
                .forEach(credentialConfig -> {
                    CredentialConfigurationSupported credentialConfigurationSupported = new CredentialConfigurationSupported();
                    credentialConfigurationSupported.setFormat(credentialConfig.getCredentialFormat());
                    credentialConfigurationSupported.setScope(credentialConfig.getScope());
                    credentialConfigurationSupported.setCryptographicBindingMethodsSupported(credentialConfig.getCryptographicBindingMethodsSupported());
                    credentialConfigurationSupported.setCredentialSigningAlgValuesSupported(credentialConfig.getCredentialSigningAlgValuesSupported());
                    credentialConfigurationSupported.setProofTypesSupported(credentialConfig.getProofTypesSupported());

                    CredentialDisplayDTO credentialDisplayDTO = new CredentialDisplayDTO();
                    credentialDisplayDTO.setBackgroundColor(credentialConfig.getDisplay().getBackgroundColor());
                    credentialDisplayDTO.setName(credentialConfig.getDisplay().getName());
                    credentialDisplayDTO.setLogo(credentialConfig.getDisplay().getLogo());
                    credentialDisplayDTO.setLocale(credentialConfig.getDisplay().getLocale());
                    credentialDisplayDTO.setTextColor(credentialConfig.getDisplay().getTextColor());
                    credentialConfigurationSupported.setDisplay(credentialDisplayDTO);
                    credentialConfigurationSupported.setOrder(credentialConfig.getOrder());

                    CredentialDefinition credentialDefinition = new CredentialDefinition();
                    credentialDefinition.setType(credentialConfig.getCredentialType());
                    credentialDefinition.setContext(credentialConfig.getContext());
                    credentialDefinition.setCredentialSubject(credentialConfig.getCredentialSubject());
                    credentialConfigurationSupported.setCredentialDefinition(credentialDefinition);

                    String credentialType = credentialConfig.getCredentialType().get(1);

                    credentialConfigurationSupportedMap.put(credentialType, credentialConfigurationSupported);
                });

        credentialIssuerMetadata.setCredentialConfigurationSupported(credentialConfigurationSupportedMap);
        return credentialIssuerMetadata;
    }


//    @Override
//    public CredentialIssuerMetadata fetchCredentialIssuerMetadata(String version) {
//        LinkedHashMap<String, Object> originalIssuerMetadata = new LinkedHashMap<>(issuerMetadata.get("latest"));
//
//        CredentialIssuerMetadata credentialIssuerMetadata = new CredentialIssuerMetadata();
//        credentialIssuerMetadata.setCredentialIssuer((String) originalIssuerMetadata.get("credential_issuer"));
//        credentialIssuerMetadata.setAuthorizationServers((List<String>) originalIssuerMetadata.get("authorization_servers"));
//        credentialIssuerMetadata.setCredentialEndpoint((String) originalIssuerMetadata.get("credential_endpoint"));
//        credentialIssuerMetadata.setDisplay((List<Map<String, String>>) originalIssuerMetadata.get("display"));
//
//        Map<String, CredentialConfigurationSupported> credentialConfigurationSupported = (Map<String, CredentialConfigurationSupported>) originalIssuerMetadata.get("credential_configurations_supported");
//        credentialIssuerMetadata.setCredentialConfigurationSupported(credentialConfigurationSupported);
//
//        return credentialIssuerMetadata;
//    }
}
