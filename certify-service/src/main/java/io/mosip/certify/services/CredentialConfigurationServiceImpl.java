/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.danubetech.dataintegrity.suites.DataIntegrityProofDataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import io.mosip.certify.validators.credentialconfigvalidators.LdpVcCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.MsoMdocCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.SdJwtCredentialConfigValidator;
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

    @Value("${mosip.certify.domain.url:}")
    private String credentialIssuer;

    @Value("${mosip.certify.authorization.url}")
    private String authUrl;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.plugin-mode}")
    private String pluginMode;

    @Value("#{${mosip.certify.credential-config.issuer.display}}")
    private List<Map<String, String>> issuerDisplay;

    @Value("#{${mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes:{}}}")
    private List<String> allowedCredentialStatusPurposes;

    @Value("#{${mosip.certify.credential-config.cryptographic-binding-methods-supported}}")
    private LinkedHashMap<String, List<String>> cryptographicBindingMethodsSupportedMap;

    @Value("#{${mosip.certify.credential-config.credential-signing-alg-values-supported}}")
    private LinkedHashMap<String, List<String>> credentialSigningAlgValuesSupportedMap;

    @Value("#{${mosip.certify.credential-config.proof-types-supported}}")
    private LinkedHashMap<String, Object> proofTypesSupported;

    @Value("#{${mosip.certify.signature-algo.key-alias-mapper}}")
    private Map<String, List<List<String>>> keyAliasMapper;

    private static final String CREDENTIAL_CONFIG_CACHE_NAME = "credentialConfig";

    @Override
    public CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) {
        validateCredentialConfiguration(credentialConfigurationDTO, true);

        CredentialConfig credentialConfig = credentialConfigMapper.toEntity(credentialConfigurationDTO);
        credentialConfig.setConfigId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);


        credentialConfig.setCryptographicBindingMethodsSupported(cryptographicBindingMethodsSupportedMap.get(credentialConfig.getCredentialFormat()));
        credentialConfig.setCredentialSigningAlgValuesSupported(Collections.singletonList(credentialConfig.getSignatureCryptoSuite()));
        credentialConfig.setProofTypesSupported(proofTypesSupported);

        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Added credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getCredentialConfigKeyId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());

        return credentialConfigResponse;
    }

    private void validateCredentialConfiguration(CredentialConfigurationDTO credentialConfig, boolean shouldCheckDuplicate) {

        if (credentialConfig.getCredentialStatusPurposes() != null && credentialConfig.getCredentialStatusPurposes().size() > 1){
            throw new CertifyException("MULTIPLE_STATUS_PURPOSES_NOT_SUPPORTED", "Multiple credential status purposes are not supported. Please specify only one.");
        }

        if (credentialConfig.getCredentialStatusPurposes() != null && !credentialConfig.getCredentialStatusPurposes().isEmpty() && !allowedCredentialStatusPurposes.contains(credentialConfig.getCredentialStatusPurposes().getFirst())) {
            throw new CertifyException("INVALID_STATUS_PURPOSE", "Invalid credential status purpose. Allowed values are: " + allowedCredentialStatusPurposes);
        }

        if(pluginMode.equals("DataProvider") && (credentialConfig.getVcTemplate() == null || credentialConfig.getVcTemplate().isEmpty())) {
            throw new CertifyException("CREDENTIAL_TEMPLATE_REQUIRED", "A Credential Template is required for issuers using the Data Provider plugin.");
        }

        switch (credentialConfig.getCredentialFormat()) {
            case VCFormats.LDP_VC:
                if (!LdpVcCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException("LDP_VC_MANDATORY_FIELDS_MISSING", "Fields context, credentialType, and signatureCryptoSuite are mandatory for the ldp_vc format.");
                }
                if(shouldCheckDuplicate && LdpVcCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException("LDP_VC_CONFIG_EXISTS", "Configuration already exists for the specified context and credentialType.");
                }
                validateKeyAliasMapperConfiguration(credentialConfig);
                break;
            case VCFormats.MSO_MDOC:
                if (!MsoMdocCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException("MSO_MDOC_MANDATORY_FIELDS_MISSING", "Fields doctype and signatureCryptoSuite are mandatory for the mso_mdoc format.");
                }
                if(shouldCheckDuplicate && MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException("MSO_MDOC_CONFIG_EXISTS", "Configuration already exists for the specified doctype.");
                }
                break;
            case VCFormats.VC_SD_JWT:
                if (!SdJwtCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException("VC_SD_JWT_MANDATORY_FIELDS_MISSING", "Fields vct and signatureAlgo are mandatory for the vc+sd-jwt format.");
                }
                if(shouldCheckDuplicate && SdJwtCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException("VC_SD_JWT_CONFIG_EXISTS", "Configuration already exists for the specified vct.");
                }
                break;
            default:
                throw new CertifyException("UNSUPPORTED_FORMAT", "Unsupported credential format: " + credentialConfig.getCredentialFormat());
        }
    }

    private void validateKeyAliasMapperConfiguration(CredentialConfigurationDTO credentialConfig) {
        if(pluginMode.equals("VCIssuance")) {
            return;
        }
        String signatureCryptoSuite = credentialConfig.getSignatureCryptoSuite();
        String signatureAlgo = credentialConfig.getSignatureAlgo();

        if(signatureCryptoSuite != null) {
            if(!credentialSigningAlgValuesSupportedMap.containsKey(signatureCryptoSuite)) {
                throw new CertifyException("UNSUPPORTED_CRYPTO_SUITE", "Unsupported signature crypto suite: " + signatureCryptoSuite);
            }

            List<String> signatureAlgos = credentialSigningAlgValuesSupportedMap.get(signatureCryptoSuite);
            if(signatureAlgo == null ) {
                signatureAlgo = signatureAlgos.getFirst();
                credentialConfig.setSignatureAlgo(signatureAlgo);
            } else if(!signatureAlgos.contains(signatureAlgo)) {
                throw new CertifyException("UNSUPPORTED_SIGNATURE_ALGO", "Signature algorithm " + signatureAlgo + " is not supported for the crypto suite: " + signatureCryptoSuite);
            }
        }

        List<List<String>> keyAliasList = keyAliasMapper.get(credentialConfig.getSignatureAlgo());
        if (keyAliasList == null || keyAliasList.isEmpty()) {
            throw new CertifyException("KEY_CHOOSER_CONFIG_NOT_FOUND", "No key chooser configuration found for the signature crypto suite: " + credentialConfig.getSignatureCryptoSuite());
        }

        boolean isMatch = keyAliasList.stream()
                .anyMatch(pair ->
                        credentialConfig.getKeyManagerAppId() != null &&
                        pair.getFirst().equals(credentialConfig.getKeyManagerAppId()) &&
                        credentialConfig.getKeyManagerRefId() != null &&
                        pair.getLast().equals(credentialConfig.getKeyManagerRefId()));

        if (!isMatch) {
            throw new CertifyException("KEY_CHOOSER_APP_REF_NOT_FOUND", "No matching appId and refId found in the key chooser configuration.");
        }
    }

    @Override
    public CredentialConfigurationDTO getCredentialConfigurationById(String credentialConfigKeyId) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if(optional.isEmpty()) {
            throw new CredentialConfigException("CONFIG_NOT_FOUND_BY_ID", "Configuration not found for the provided ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();
        if(!credentialConfig.getStatus().equals(Constants.ACTIVE)) {
            throw new CertifyException("CONFIG_NOT_ACTIVE", "Configuration is inactive.");
        }

        return credentialConfigMapper.toDto(credentialConfig);
    }

    /**
     * NOTE: Using @credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#id) will cause
     * an additional database lookup for CredentialConfig by id within the key generator.
     * This is a trade-off for using declarative @CacheEvict on this method signature.
     * The alternative is manual CacheManager.evict() after fetching the object once in this method.
     */
    @Override
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME, key = "@credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#credentialConfigKeyId)", condition = "#credentialConfigKeyId != null")
    public CredentialConfigResponse updateCredentialConfiguration(String credentialConfigKeyId, CredentialConfigurationDTO credentialConfigurationDTO){
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if(optional.isEmpty()) {
            log.warn("Configuration not found for update with id: {}", credentialConfigKeyId);
            throw new CredentialConfigException("CONFIG_NOT_FOUND_FOR_UPDATE", "Configuration not found for update with ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();
        credentialConfigMapper.updateEntityFromDto(credentialConfigurationDTO, credentialConfig);

        validateCredentialConfiguration(credentialConfigMapper.toDto(credentialConfig), false);

        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Updated credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getCredentialConfigKeyId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());

        return credentialConfigResponse;
    }

    /**
     * NOTE: Using @credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#id) will cause
     * an additional database lookup for CredentialConfig by id within the key generator.
     * This is a trade-off for using declarative @CacheEvict on this method signature.
     */
    @Override
    @Transactional
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME,
            key = "@credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#credentialConfigKeyId)",
            beforeInvocation = true)
    public String deleteCredentialConfigurationById(String credentialConfigKeyId) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId) ;

        if(optional.isEmpty()) {
            log.warn("Configuration not found for delete with id: {}", credentialConfigKeyId);
            throw new CredentialConfigException("CONFIG_NOT_FOUND_FOR_DELETE", "Configuration not found for delete with ID: " + credentialConfigKeyId);
        }

        // The object is fetched once here.
        // The @CacheEvict's key SpEL will cause CredentialCacheKeyGenerator to fetch it again.
        credentialConfigRepository.delete(optional.get());
        log.info("Deleted credential configuration: {}", credentialConfigKeyId);
        return credentialConfigKeyId;
    }

    @Override
    public CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata(String version) {
        List<CredentialConfig> credentialConfigList = credentialConfigRepository.findAll();

        if ("latest".equals(version)) {
            CredentialIssuerMetadataVD13DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD13DTO();
            Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();
            credentialConfigList.stream()
                    .filter(config -> Constants.ACTIVE.equals(config.getStatus()))
                    .forEach(credentialConfig -> {
                        CredentialConfigurationSupportedDTO credentialConfigurationSupported = mapToSupportedDTO(credentialConfig);
                        if (credentialConfig.getSignatureCryptoSuite() != null) {
                            credentialConfigurationSupported.setCredentialSigningAlgValuesSupported(credentialSigningAlgValuesSupportedMap.get(credentialConfig.getSignatureCryptoSuite()));
                        } else {
                            credentialConfigurationSupported.setCredentialSigningAlgValuesSupported(Collections.singletonList(credentialConfig.getSignatureAlgo()));
                        }
                        credentialConfigurationSupportedMap.put(credentialConfig.getCredentialConfigKeyId(), credentialConfigurationSupported);
                    });
            credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap);
            credentialIssuerMetadata.setCredentialIssuer(credentialIssuer);
            credentialIssuerMetadata.setAuthorizationServers(Collections.singletonList(authUrl));
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
            credentialIssuerMetadata.setAuthorizationServers(Collections.singletonList(authUrl));
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
            credentialIssuerMetadata.setAuthorizationServers(Collections.singletonList(authUrl));
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
        credentialConfigurationSupported.setCryptographicBindingMethodsSupported(credentialConfig.getCryptographicBindingMethodsSupported());
        credentialConfigurationSupported.setProofTypesSupported(credentialConfig.getProofTypesSupported());
        credentialConfigurationSupported.setDisplay(credentialConfigurationDTO.getMetaDataDisplay());
        credentialConfigurationSupported.setOrder(credentialConfigurationDTO.getDisplayOrder());

        if (VCFormats.LDP_VC.equals(credentialConfig.getCredentialFormat())) {
            CredentialDefinition credentialDefinition = new CredentialDefinition();
            credentialDefinition.setType(credentialConfigurationDTO.getCredentialTypes());
            credentialDefinition.setContext(credentialConfigurationDTO.getContextURLs());
            if (credentialConfig.getCredentialSubject() != null) {
                credentialDefinition.setCredentialSubject(new HashMap<>(credentialConfig.getCredentialSubject()));
            }
            credentialConfigurationSupported.setCredentialDefinition(credentialDefinition);
        } else if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            if (credentialConfig.getMsoMdocClaims() != null) {
                credentialConfigurationSupported.setClaims(new HashMap<>(new HashMap<>(credentialConfig.getMsoMdocClaims())));
            }
            credentialConfigurationSupported.setDocType(credentialConfig.getDocType());
        } else if (VCFormats.VC_SD_JWT.equals(credentialConfig.getCredentialFormat())) {
            if (credentialConfig.getSdJwtClaims() != null) {
                credentialConfigurationSupported.setClaims(new HashMap<>(credentialConfig.getSdJwtClaims()));
            }
            credentialConfigurationSupported.setVct(credentialConfig.getSdJwtVct());
        }

        return credentialConfigurationSupported;
    }
}