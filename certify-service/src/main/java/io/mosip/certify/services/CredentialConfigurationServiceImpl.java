package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.CredentialDisplay;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.CredentialDisplayRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Component
public class CredentialConfigurationServiceImpl implements CredentialConfigurationService {

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

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
        CredentialConfig credentialConfig = new CredentialConfig();
        credentialConfig.setId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);
        credentialConfig.setVcTemplate(credentialConfigurationDTO.getVcTemplate());
        credentialConfig.setContext(credentialConfigurationDTO.getContext());
        credentialConfig.setCredentialType(credentialConfigurationDTO.getCredentialType());
        credentialConfig.setCredentialFormat(credentialConfigurationDTO.getCredentialFormat());
        credentialConfig.setDidUrl(credentialConfigurationDTO.getDidUrl());

        CredentialDisplay credentialDisplayEntity = new CredentialDisplay();
        credentialDisplayEntity.setBackgroundColor(credentialConfigurationDTO.getDisplay().getBackgroundColor());
        credentialDisplayEntity.setName(credentialConfigurationDTO.getDisplay().getName());
        credentialDisplayEntity.setLogo(credentialConfigurationDTO.getDisplay().getLogo());
        credentialDisplayEntity.setLocale(credentialConfigurationDTO.getDisplay().getLocale());
        credentialDisplayEntity.setTextColor(credentialConfigurationDTO.getDisplay().getTextColor());
        credentialConfig.setDisplay(credentialDisplayEntity);

        credentialConfig.setOrder(credentialConfigurationDTO.getOrder());
        credentialConfig.setScope(credentialConfigurationDTO.getScope());
        credentialConfig.setCryptographicBindingMethodsSupported(credentialConfigurationDTO.getCryptographicBindingMethodsSupported());
        credentialConfig.setCredentialSigningAlgValuesSupported(credentialConfigurationDTO.getCredentialSigningAlgValuesSupported());
        credentialConfig.setProofTypesSupported(credentialConfigurationDTO.getProofTypesSupported());
        credentialConfig.setCredentialSubject(credentialConfigurationDTO.getCredentialSubject());
//        credentialConfig.setPluginConfigurations(credentialConfigurationDTO.getPluginConfigurations());
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

        CredentialConfigurationDTO credentialConfigurationDTO = new CredentialConfigurationDTO();
        credentialConfigurationDTO.setVcTemplate(credentialConfig.getVcTemplate());
        credentialConfigurationDTO.setContext(credentialConfig.getContext());
        credentialConfigurationDTO.setCredentialType(credentialConfig.getCredentialType());
        credentialConfigurationDTO.setCredentialFormat(credentialConfig.getCredentialFormat());
        credentialConfigurationDTO.setDidUrl(credentialConfig.getDidUrl());

        CredentialDisplayDTO credentialDisplayDTO = new CredentialDisplayDTO();
        credentialDisplayDTO.setBackgroundColor(credentialConfig.getDisplay().getBackgroundColor());
        credentialDisplayDTO.setName(credentialConfig.getDisplay().getName());
        credentialDisplayDTO.setLogo(credentialConfig.getDisplay().getLogo());
        credentialDisplayDTO.setLocale(credentialConfig.getDisplay().getLocale());
        credentialDisplayDTO.setTextColor(credentialConfig.getDisplay().getTextColor());
        credentialConfigurationDTO.setDisplay(credentialDisplayDTO);

        credentialConfigurationDTO.setOrder(credentialConfig.getOrder());
        credentialConfigurationDTO.setScope(credentialConfig.getScope());
        credentialConfigurationDTO.setCryptographicBindingMethodsSupported(credentialConfig.getCryptographicBindingMethodsSupported());
        credentialConfigurationDTO.setCredentialSigningAlgValuesSupported(credentialConfig.getCredentialSigningAlgValuesSupported());
        credentialConfigurationDTO.setProofTypesSupported(credentialConfig.getProofTypesSupported());
        credentialConfigurationDTO.setCredentialSubject(credentialConfig.getCredentialSubject());
        return credentialConfigurationDTO;
    }

    @Override
    public CredentialConfigResponse updateCredentialConfiguration(String id, CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException {
        Optional<CredentialConfig> optional = credentialConfigRepository.findById(id);

        if(optional.isEmpty()) {
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        CredentialConfig credentialConfig = optional.get();
        credentialConfig.setVcTemplate(credentialConfigurationDTO.getVcTemplate());
        credentialConfig.setContext(credentialConfigurationDTO.getContext());
        credentialConfig.setCredentialType(credentialConfigurationDTO.getCredentialType());
        credentialConfig.setCredentialFormat(credentialConfigurationDTO.getCredentialFormat());
        credentialConfig.setDidUrl(credentialConfigurationDTO.getDidUrl());

        CredentialDisplay credentialDisplayEntity = new CredentialDisplay();
        credentialDisplayEntity.setBackgroundColor(credentialConfigurationDTO.getDisplay().getBackgroundColor());
        credentialDisplayEntity.setName(credentialConfigurationDTO.getDisplay().getName());
        credentialDisplayEntity.setLogo(credentialConfigurationDTO.getDisplay().getLogo());
        credentialDisplayEntity.setLocale(credentialConfigurationDTO.getDisplay().getLocale());
        credentialDisplayEntity.setTextColor(credentialConfigurationDTO.getDisplay().getTextColor());
        credentialConfig.setDisplay(credentialDisplayEntity);

        credentialConfig.setOrder(credentialConfigurationDTO.getOrder());
        credentialConfig.setScope(credentialConfigurationDTO.getScope());
        credentialConfig.setCryptographicBindingMethodsSupported(credentialConfigurationDTO.getCryptographicBindingMethodsSupported());
        credentialConfig.setCredentialSigningAlgValuesSupported(credentialConfigurationDTO.getCredentialSigningAlgValuesSupported());
        credentialConfig.setProofTypesSupported(credentialConfigurationDTO.getProofTypesSupported());
        credentialConfig.setCredentialSubject(credentialConfigurationDTO.getCredentialSubject());
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

        CredentialConfig credentialConfig = optional.get();

        Optional<CredentialDisplay> optionalCredentialDisplay = credentialDisplayRepository.findById(credentialConfig.getDisplay().getId());
        if(optionalCredentialDisplay.isEmpty()) {
            throw new CertifyException("Credential display not found for the provided configuration id: " + id);
        }

        credentialDisplayRepository.deleteById(credentialConfig.getDisplay().getId());
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
