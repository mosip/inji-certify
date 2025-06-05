/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.TemplateId;
import io.mosip.certify.mapper.CredentialConfigMapper;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialCacheKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

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

    @Value("${mosip.certify.domain.url:}")
    private String credentialIssuerDomainUrl;

    @Value("#{'${mosip.certify.authorization.url}'.split(',')}")
    private List<String> authServers;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.plugin-mode}")
    private String pluginMode;

    @Value("#{${mosip.certify.credential-config.issuer.display}}")
    private List<Map<String, String>> issuerDisplay;

    private static final String CREDENTIAL_CONFIG_CACHE_NAME = "credentialConfig";

    @Override
    public CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException {
        CredentialConfig credentialConfig = credentialConfigMapper.toEntity(credentialConfigurationDTO);
        TemplateId templateId = new TemplateId(); // Consider constructor TemplateId(context, type, format)
        templateId.setCredentialType(credentialConfig.getCredentialType());
        templateId.setContext(credentialConfig.getContext());
        templateId.setCredentialFormat(credentialConfig.getCredentialFormat());

        Optional<CredentialConfig> optional = credentialConfigRepository.findById(templateId);

        if(optional.isPresent()) {
            log.warn("Attempt to add existing credential configuration: Type={}, Context={}, Format={}",
                    credentialConfig.getCredentialType(), credentialConfig.getContext(), credentialConfig.getCredentialFormat());
            throw new CertifyException("Credential type already exists. Try updating the credential.");
        }

        credentialConfig.setConfigId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);

        if(pluginMode.equals("DataProvider") && credentialConfig.getVcTemplate() == null) {
            throw new CertifyException("Credential Template is mandatory for this `DataProvider` plugin issuer.");
        }

        validateCredentialConfiguration(credentialConfig);
        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Added credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getConfigId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());

        return credentialConfigResponse;
    }

    private void validateCredentialConfiguration(CredentialConfig credentialConfig) {
        switch (credentialConfig.getCredentialFormat()) {
            case VCFormats.LDP_VC:
                if (credentialConfig.getCredentialSubject() == null) {
                    throw new CertifyException("CredentialSubject is mandatory for ldp_vc");
                }
                break;
            case VCFormats.MSO_MDOC:
                if (credentialConfig.getClaims() == null || credentialConfig.getDocType() == null) {
                    throw new CertifyException("Claims and Doctype are mandatory for mso_mdoc");
                }
                break;
            case VCFormats.LDP_SD_JWT:
                if (credentialConfig.getClaims() == null || credentialConfig.getVct() == null) {
                    throw new CertifyException("Claims and Vct fields are mandatory for vc+sd-jwt");
                }
                break;
            default:
                throw new CertifyException("Unsupported format: " + credentialConfig.getCredentialFormat());
        }
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

        return credentialConfigMapper.toDto(credentialConfig);
    }

    /**
     * NOTE: Using @credentialCacheKeyGenerator.generateKeyFromConfigId(#id) will cause
     * an additional database lookup for CredentialConfig by id within the key generator.
     * This is a trade-off for using declarative @CacheEvict on this method signature.
     * The alternative is manual CacheManager.evict() after fetching the object once in this method.
     */
    @Override
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME, key = "@credentialCacheKeyGenerator.generateKeyFromConfigId(#id)", condition = "#id != null")
    public CredentialConfigResponse updateCredentialConfiguration(String id, CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByConfigId(id);

        if(optional.isEmpty()) {
            log.warn("Configuration not found for update with id: {}", id);
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        CredentialConfig credentialConfig = optional.get();
        credentialConfigMapper.updateEntityFromDto(credentialConfigurationDTO, credentialConfig);
        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Updated credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getConfigId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());

        return credentialConfigResponse;
    }

    /**
     * NOTE: Using @credentialCacheKeyGenerator.generateKeyFromConfigId(#id) will cause
     * an additional database lookup for CredentialConfig by id within the key generator.
     * This is a trade-off for using declarative @CacheEvict on this method signature.
     */
    @Override
    @Transactional
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME,
            key = "@credentialCacheKeyGenerator.generateKeyFromConfigId(#id)",
            beforeInvocation = true)
    public String deleteCredentialConfigurationById(String id) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByConfigId(id);

        if(optional.isEmpty()) {
            log.warn("Configuration not found for delete with id: {}", id);
            throw new CertifyException("Configuration not found with the provided id: " + id);
        }

        // The object is fetched once here.
        // The @CacheEvict's key SpEL will cause CredentialCacheKeyGenerator to fetch it again.
        credentialConfigRepository.delete(optional.get());
        log.info("Deleted credential configuration: {}", id);
        return id;
    }

    @Override
    public CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata(String version) {
        List<CredentialConfig> credentialConfigList = credentialConfigRepository.findAll();
        if(!credentialIssuerDomainUrl.isEmpty()) {
            credentialIssuer = credentialIssuerDomainUrl;
        }

        if ("latest".equals(version)) {
            CredentialIssuerMetadataVD13DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD13DTO();
            Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();
            credentialConfigList.stream()
                    .filter(config -> Constants.ACTIVE.equals(config.getStatus()))
                    .forEach(credentialConfig -> {
                        CredentialConfigurationSupportedDTO credentialConfigurationSupported = mapToSupportedDTO(credentialConfig);
                        credentialConfigurationSupported.setCredentialSigningAlgValuesSupported(credentialConfig.getCredentialSigningAlgValuesSupported());
                        credentialConfigurationSupportedMap.put(credentialConfig.getCredentialConfigKeyId(), credentialConfigurationSupported);
                    });
            credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap);
            credentialIssuerMetadata.setCredentialIssuer(credentialIssuer);
            credentialIssuerMetadata.setAuthorizationServers(authServers);
            String credentialEndpoint = credentialIssuer + servletPath + "/issuance" + (!version.equals("latest") ? "/" + version : "") + "/credential";
            credentialIssuerMetadata.setCredentialEndpoint(credentialEndpoint);
            credentialIssuerMetadata.setDisplay(issuerDisplay);

            return credentialIssuerMetadata;
        } else if ("vd12".equals(version)) {
            CredentialIssuerMetadataVD12DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD12DTO();
            Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();
            credentialConfigList.stream()
                    .filter(config -> Constants.ACTIVE.equals(config.getStatus()))
                    .forEach(credentialConfig -> {
                        CredentialConfigurationSupportedDTO credentialConfigurationSupported = mapToSupportedDTO(credentialConfig);
                        credentialConfigurationSupported.setCryptographicSuitesSupported(credentialConfig.getCredentialSigningAlgValuesSupported());
                        credentialConfigurationSupportedMap.put(credentialConfig.getCredentialConfigKeyId(), credentialConfigurationSupported);
                    });
            credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap); // Use a different setter for vd12
            credentialIssuerMetadata.setCredentialIssuer(credentialIssuer);
            credentialIssuerMetadata.setAuthorizationServers(authServers);
            String credentialEndpoint = credentialIssuer + servletPath + "/issuance/" + version + "/credential";
            credentialIssuerMetadata.setCredentialEndpoint(credentialEndpoint);
            credentialIssuerMetadata.setDisplay(issuerDisplay);

            return credentialIssuerMetadata;
        } else if ("vd11".equals(version)) {
            CredentialIssuerMetadataVD11DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD11DTO();
            List<CredentialConfigurationSupportedDTO> credentialConfigurationSupportedList = new ArrayList<>();
            credentialConfigList.stream()
                    .filter(config -> Constants.ACTIVE.equals(config.getStatus()))
                    .forEach(credentialConfig -> {
                        CredentialConfigurationSupportedDTO credentialConfigurationSupported = mapToSupportedDTO(credentialConfig);
                        credentialConfigurationSupported.setId(credentialConfig.getCredentialConfigKeyId());
                        credentialConfigurationSupported.setCryptographicSuitesSupported(credentialConfig.getCredentialSigningAlgValuesSupported());
                        credentialConfigurationSupportedList.add(credentialConfigurationSupported);
                    });
            credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedList); // Use a different setter for vd11
            credentialIssuerMetadata.setCredentialIssuer(credentialIssuer);
            credentialIssuerMetadata.setAuthorizationServers(authServers);
            String credentialEndpoint = credentialIssuer + servletPath + "/issuance/" + version + "/credential";
            credentialIssuerMetadata.setCredentialEndpoint(credentialEndpoint);
            credentialIssuerMetadata.setDisplay(issuerDisplay);

            return credentialIssuerMetadata;
        }

        throw new CertifyException("Unsupported version: " + version);
    }

    private CredentialConfigurationSupportedDTO mapToSupportedDTO(CredentialConfig credentialConfig) {
        CredentialConfigurationSupportedDTO credentialConfigurationSupported = new CredentialConfigurationSupportedDTO();
        CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);
        credentialConfigurationSupported.setFormat(credentialConfigurationDTO.getCredentialFormat());
        credentialConfigurationSupported.setScope(credentialConfigurationDTO.getScope());
        credentialConfigurationSupported.setCryptographicBindingMethodsSupported(credentialConfigurationDTO.getCryptographicBindingMethodsSupported());
        credentialConfigurationSupported.setProofTypesSupported(credentialConfigurationDTO.getProofTypesSupported());
        credentialConfigurationSupported.setDisplay(credentialConfigurationDTO.getDisplay());
        credentialConfigurationSupported.setOrder(credentialConfigurationDTO.getOrder());

        if (VCFormats.LDP_VC.equals(credentialConfig.getCredentialFormat())) {
            CredentialDefinition credentialDefinition = new CredentialDefinition();
            credentialDefinition.setType(credentialConfigurationDTO.getCredentialType());
            credentialDefinition.setContext(credentialConfigurationDTO.getContext());
            credentialDefinition.setCredentialSubject(credentialConfig.getCredentialSubject());
            credentialConfigurationSupported.setCredentialDefinition(credentialDefinition);
        } else if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            credentialConfigurationSupported.setClaims(credentialConfig.getClaims());
            credentialConfigurationSupported.setDocType(credentialConfig.getDocType());
        } else if (VCFormats.LDP_SD_JWT.equals(credentialConfig.getCredentialFormat())) {
            credentialConfigurationSupported.setClaims(credentialConfig.getClaims());
            credentialConfigurationSupported.setVct(credentialConfig.getCredentialConfigKeyId());
        }

        return credentialConfigurationSupported;
    }
}