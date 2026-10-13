package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.core.exception.CredentialConfigValidationException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.attributes.Claims;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import io.mosip.certify.utils.CredentialConfigMetadataResolver;
import io.mosip.certify.validators.credentialconfigvalidators.CredentialConfigMetadataValidator;
import io.mosip.certify.validators.credentialconfigvalidators.LdpVcCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.MsoMdocCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.QrSettingsValidator;
import io.mosip.certify.validators.credentialconfigvalidators.SdJwtCredentialConfigValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import java.util.*;
import java.util.stream.Collectors;
import com.nimbusds.jose.JWSAlgorithm;
import com.authlete.cose.constants.COSEAlgorithms;

@Slf4j
@Component
@Transactional
public class CredentialConfigurationServiceImpl implements CredentialConfigurationService {

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private CredentialConfigMapper credentialConfigMapper;

    @Value("${mosip.certify.domain.url}")
    private String credentialIssuer;

    @Value("${mosip.certify.allow-c-nonce:false}")
    private boolean allowCNonce;

    @Value("${mosip.certify.authorization.url}")
    private String authUrl;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.plugin-mode}")
    private String pluginMode;

    @Value("#{${mosip.certify.credential-config.issuer.display}}")
    private List<Map<String, Object>> issuerDisplay;

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

    @Value("#{${mosip.certify.credential-config.as-mapping:{}}}")
    private Map<String, String> authorizationServerMapping;

    private static final String CREDENTIAL_CONFIG_CACHE_NAME = "credentialConfig";

    // The algorithms an mso_mdoc issuer may sign with. Only ES256 is supported, as HAIP requires for
    // an mdoc's issuerAuth; RS256 and ES256K are outside ISO 18013-5 altogether.
    private static final Map<String, Integer> COSE_ALGORITHM_INTEGER_MAP = Map.of(
        JWSAlgorithm.ES256.getName(), COSEAlgorithms.ES256
    );

    @Override
    public CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) {
        validateCredentialConfiguration(credentialConfigurationDTO, true);

        CredentialConfig credentialConfig = credentialConfigMapper.toEntity(credentialConfigurationDTO);
        validateAndApplyCredentialConfigMetadataAttributes(credentialConfigurationDTO, credentialConfig);
        return saveCredentialConfiguration(credentialConfig);
    }

    private CredentialConfigResponse saveCredentialConfiguration(CredentialConfig credentialConfig) {
        credentialConfig.setConfigId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);

        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Added credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getCredentialConfigKeyId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());

        return credentialConfigResponse;
    }

    private void validateCredentialConfiguration(CredentialConfigurationDTO credentialConfig, boolean shouldCheckDuplicate) {

        validateCommonCredentialConfig(credentialConfig.getCredentialStatusPurposes(),credentialConfig.getVcTemplate(),credentialConfig.getQrSettings(),credentialConfig.getQrSignatureAlgo());

        switch (credentialConfig.getCredentialFormat()) {
            case VCFormats.LDP_VC:
                if (!LdpVcCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException(ErrorConstants.LDP_VC_MANDATORY_FIELDS_MISSING, "Fields context, credentialType, and signatureCryptoSuite are mandatory for the ldp_vc format.");
                }
                if(shouldCheckDuplicate && LdpVcCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.LDP_VC_CONFIG_EXISTS, "Configuration already exists for the specified context and credentialType.");
                }
                validateKeyAliasMapperConfiguration(credentialConfig);
                break;
            case VCFormats.MSO_MDOC:
                if (!MsoMdocCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException(ErrorConstants.MSO_MDOC_MANDATORY_FIELDS_MISSING, "Fields doctype and signatureCryptoSuite are mandatory for the mso_mdoc format.");
                }
                if(shouldCheckDuplicate && MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.MSO_MDOC_CONFIG_EXISTS, "Configuration already exists for the specified doctype.");
                }
                break;
            case VCFormats.DC_SD_JWT:
                if (!SdJwtCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException(ErrorConstants.DC_SD_JWT_MANDATORY_FIELDS_MISSING, "Fields vct and signatureAlgo are mandatory for the dc+sd-jwt format.");
                }
                if(shouldCheckDuplicate && SdJwtCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.DC_SD_JWT_CONFIG_EXISTS, "Configuration already exists for the specified vct.");
                }
                break;
            default:
                throw new CertifyException(ErrorConstants.UNSUPPORTED_FORMAT, "Unsupported credential format: " + credentialConfig.getCredentialFormat());
        }
    }

    private void validateCommonCredentialConfig(
            List<String> credentialStatusPurposes,
            String vcTemplate,
            List<Map<String, Object>> qrSettings,
            String qrSignatureAlgo){
        if (credentialStatusPurposes != null && credentialStatusPurposes.size() > 1){
            throw new CertifyException(ErrorConstants.MULTIPLE_STATUS_PURPOSES_NOT_SUPPORTED, "Multiple credential status purposes are not supported. Please specify only one.");
        }

        if (credentialStatusPurposes != null && !credentialStatusPurposes.isEmpty() && !allowedCredentialStatusPurposes.contains(credentialStatusPurposes.getFirst())) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE, "Invalid credential status purpose. Allowed values are: " + allowedCredentialStatusPurposes);
        }

        if(pluginMode.equals("DataProvider") && (vcTemplate == null || vcTemplate.isEmpty())) {
            throw new CertifyException(ErrorConstants.CREDENTIAL_TEMPLATE_REQUIRED, "A Credential Template is required for issuers using the Data Provider plugin.");
        }

        if(qrSettings == null || qrSettings.isEmpty()) {
            if(qrSignatureAlgo != null) {
                throw new CertifyException(ErrorConstants.QR_SIGNATURE_ALGO_NOT_ALLOWED, "QR signature algorithm is not allowed when QR settings are not set.");

            }
        } else {
            if (qrSignatureAlgo != null && !qrSignatureAlgo.isEmpty() && !keyAliasMapper.containsKey(qrSignatureAlgo)) {
                throw new CertifyException(ErrorConstants.INVALID_QR_SIGNING_ALGORITHM, "The algorithm " + qrSignatureAlgo + " is not supported for QR signing. The supported values are: " + keyAliasMapper.keySet());
            }
            QrSettingsValidator.validateQrSettings(qrSettings, vcTemplate);
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
                throw new CertifyException(ErrorConstants.UNSUPPORTED_CRYPTO_SUITE, "Unsupported signature crypto suite: " + signatureCryptoSuite);
            }

            List<String> signatureAlgos = credentialSigningAlgValuesSupportedMap.get(signatureCryptoSuite);
            if(signatureAlgo == null ) {
                signatureAlgo = signatureAlgos.getFirst();
                credentialConfig.setSignatureAlgo(signatureAlgo);
            } else if(!signatureAlgos.contains(signatureAlgo)) {
                throw new CertifyException(ErrorConstants.UNSUPPORTED_SIGNATURE_ALGO, "Signature algorithm " + signatureAlgo + " is not supported for the crypto suite: " + signatureCryptoSuite);
            }
        }

        List<List<String>> keyAliasList = keyAliasMapper.get(credentialConfig.getSignatureAlgo());
        if (keyAliasList == null || keyAliasList.isEmpty()) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND, "No key chooser configuration found for the signature crypto suite: " + credentialConfig.getSignatureCryptoSuite());
        }

        boolean isMatch = keyAliasList.stream()
                .anyMatch(pair ->
                        credentialConfig.getKeyManagerAppId() != null &&
                                pair.getFirst().equals(credentialConfig.getKeyManagerAppId()) &&
                                credentialConfig.getKeyManagerRefId() != null &&
                                pair.getLast().equals(credentialConfig.getKeyManagerRefId()));

        if (!isMatch) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_APP_REF_NOT_FOUND, "No matching appId and refId found in the key chooser configuration.");
        }
    }

    /**
     * Validates cryptographic_binding_methods_supported, credential_signing_alg_values_supported and
     * proof_types_supported and stores them on the entity as requested.
     * <p>
     * All three are mandatory on add and on update. The deployment configuration is the allow-list every
     * value is checked against, and never a source of values: nothing is filled in from it, so what a
     * configuration advertises is always what the issuer declared for it.
     * <p>
     * A value listed more than once is kept once, in the order first given, and the request is not
     * rejected for it. This happens before validation, so a repeated value is also reported only once.
     * <p>
     * Every failure across all three attributes is collected before anything is stored, so the caller
     * sees the whole payload's problems at once and nothing is partially saved.
     */
    private void validateAndApplyCredentialConfigMetadataAttributes(CredentialConfigurationDTO request, CredentialConfig credentialConfig) {
        List<String> bindingMethods = getDistinct(request.getCryptographicBindingMethodsSupported());
        List<String> signingAlgs = getDistinct(request.getCredentialSigningAlgValuesSupported());
        Map<String, Object> proofTypes = getDistinctProofSigningAlgs(request.getProofTypesSupported());

        List<io.mosip.certify.core.dto.Error> errors = new ArrayList<>();
        CredentialConfigMetadataValidator.validateBindingMethods(bindingMethods,
                credentialConfig.getCredentialFormat(), cryptographicBindingMethodsSupportedMap, errors);
        CredentialConfigMetadataValidator.validateSigningAlgs(signingAlgs,
                credentialConfig.getSignatureCryptoSuite(), credentialSigningAlgValuesSupportedMap,
                keyAliasMapper, errors);
        CredentialConfigMetadataValidator.validateCoseSigningAlgs(signingAlgs,
                credentialConfig.getCredentialFormat(), COSE_ALGORITHM_INTEGER_MAP.keySet(), errors);
        CredentialConfigMetadataValidator.validateProofTypes(proofTypes, proofTypesSupported, errors);

        if (!errors.isEmpty()) {
            throw new CredentialConfigValidationException(errors);
        }

        credentialConfig.setCryptographicBindingMethodsSupported(bindingMethods);
        credentialConfig.setCredentialSigningAlgValuesSupported(signingAlgs);
        credentialConfig.setProofTypesSupported(proofTypes);
    }

    private static <T> List<T> getDistinct(List<T> values) {
        return values == null ? null : new ArrayList<>(new LinkedHashSet<>(values));
    }

    /**
     * The proof types with each proof_signing_alg_values_supported list de-duplicated. A proof type name
     * cannot repeat, being a JSON object key. Any other shape is passed through unchanged for the
     * validator to report.
     */
    private static Map<String, Object> getDistinctProofSigningAlgs(Map<String, Object> proofTypes) {
        if (proofTypes == null) {
            return null;
        }
        Map<String, Object> result = new LinkedHashMap<>();
        proofTypes.forEach((proofType, detail) -> {
            if (detail instanceof Map<?, ?> detailMap
                    && detailMap.get(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED) instanceof List<?> algs) {
                Map<Object, Object> distinctDetail = new LinkedHashMap<>(detailMap);
                distinctDetail.put(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, getDistinct(algs));
                result.put(proofType, distinctDetail);
            } else {
                result.put(proofType, detail);
            }
        });
        return result;
    }

    @Override
    public CredentialConfigurationDTO getCredentialConfigurationById(String credentialConfigKeyId) {
        CredentialConfig credentialConfig = getActiveCredentialConfig(credentialConfigKeyId);

        CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);
        // All three are always returned. The stored values are returned as they are; a configuration created
        // before these attributes were stored carries none, and keeps returning the values it always has.
        if (credentialConfigurationDTO.getCryptographicBindingMethodsSupported() == null) {
            credentialConfigurationDTO.setCryptographicBindingMethodsSupported(
                    CredentialConfigMetadataResolver.deriveBindingMethods(credentialConfig.getCredentialFormat(),
                            cryptographicBindingMethodsSupportedMap));
        }
        credentialConfigurationDTO.setCredentialSigningAlgValuesSupported(
                CredentialConfigMetadataResolver.resolveStoredSigningAlgs(credentialConfig, credentialSigningAlgValuesSupportedMap));
        Map<String, Object> storedProofTypes = credentialConfigurationDTO.getProofTypesSupported();
        credentialConfigurationDTO.setProofTypesSupported(CredentialConfigMetadataResolver.resolveProofTypes(
                storedProofTypes == null || storedProofTypes.isEmpty() ? proofTypesSupported : storedProofTypes,
                proofTypesSupported));
        return credentialConfigurationDTO;
    }

    private CredentialConfig getActiveCredentialConfig(String credentialConfigKeyId) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if(optional.isEmpty()) {
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Configuration not found for the provided ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();
        if(!credentialConfig.getStatus().equals(Constants.ACTIVE)) {
            throw new CertifyException(ErrorConstants.CONFIG_NOT_ACTIVE, "Configuration is inactive.");
        }
        return credentialConfig;
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
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_FOR_UPDATE, "Configuration not found for update with ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();
        credentialConfigMapper.updateEntityFromDto(credentialConfigurationDTO, credentialConfig);

        validateCredentialConfiguration(credentialConfigMapper.toDto(credentialConfig), false);

        validateAndApplyCredentialConfigMetadataAttributes(credentialConfigurationDTO, credentialConfig);

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
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_FOR_DELETE, "Configuration not found for delete with ID: " + credentialConfigKeyId);
        }

        // The object is fetched once here.
        // The @CacheEvict's key SpEL will cause CredentialCacheKeyGenerator to fetch it again.
        credentialConfigRepository.delete(optional.get());
        log.info("Deleted credential configuration: {}", credentialConfigKeyId);
        return credentialConfigKeyId;
    }

    @Override
    public CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata() {
        List<CredentialConfig> credentialConfigList = credentialConfigRepository.findAll()
                .stream()
                .filter(config -> Constants.ACTIVE.equals(config.getStatus()))
                .toList();

        return buildMetadata(credentialConfigList);
    }

    /**
     * Checks every active configuration once the application is up, so a stored configuration that cannot
     * be advertised is reported at startup rather than first noticed by a wallet. It is logged, not fatal:
     * the metadata endpoint skips such a configuration and keeps serving the rest.
     *
     * <p>It runs outside the class-level transaction. Inside it, a failed load would mark that transaction
     * rollback-only, and committing it would then fail startup even though the error was caught.
     */
    @EventListener(ApplicationReadyEvent.class)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void validateStoredConfigurations() {
        List<CredentialConfig> active;
        try {
            active = credentialConfigRepository.findAll()
                    .stream()
                    .filter(config -> Constants.ACTIVE.equals(config.getStatus()))
                    .toList();
        } catch (RuntimeException e) {
            log.error("Stored credential configurations could not be loaded for the startup check", e);
            return;
        }
        long invalid = active.stream().filter(config -> tryBuildSupportedDTO(config) == null).count();
        if (invalid > 0) {
            log.error("{} of {} active credential configurations cannot be advertised in the issuer metadata",
                    invalid, active.size());
        }
    }

    private CredentialIssuerMetadataDTO buildMetadata(List<CredentialConfig> credentialConfigList) {
        CredentialIssuerMetadataDTO credentialIssuerMetadata = new CredentialIssuerMetadataDTO();
        Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();

        for (CredentialConfig credentialConfig : credentialConfigList) {
            CredentialConfigurationSupportedDTO dto = tryBuildSupportedDTO(credentialConfig);
            if (dto != null) {
                credentialConfigurationSupportedMap.put(credentialConfig.getCredentialConfigKeyId(), dto);
            }
        }

        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap);
        populateCommonMetadataFields(credentialIssuerMetadata);
        return credentialIssuerMetadata;
    }

    /**
     * One configuration that cannot be advertised must not take the issuer metadata down for every
     * credential type, so the failure is logged against that configuration and it is left out.
     *
     * @return the advertised entry, or {@code null} when this configuration cannot be advertised
     */
    private CredentialConfigurationSupportedDTO tryBuildSupportedDTO(CredentialConfig credentialConfig) {
        try {
            return buildSupportedDTO(credentialConfig);
        } catch (RuntimeException e) {
            log.error("Credential configuration {} is left out of the issuer metadata: {}",
                    credentialConfig.getCredentialConfigKeyId(), e.getMessage(), e);
            return null;
        }
    }

    private CredentialConfigurationSupportedDTO buildSupportedDTO(CredentialConfig credentialConfig) {
        CredentialConfigurationSupportedDTO dto = mapToSupportedDTO(credentialConfig);
        // The values stored against this configuration are what gets advertised, so an issuer's
        // explicit selection reaches wallets instead of being rebuilt from configuration.
        List<String> algs = CredentialConfigMetadataResolver.resolveStoredSigningAlgs(credentialConfig, credentialSigningAlgValuesSupportedMap);
        if (algs.isEmpty()) {
            algs = null;
        }

        // A configuration written before these attributes were stored carries neither, so the same
        // defaults the Get API resolves are applied here too - what a wallet reads and what an
        // issuer reads back stay the same.
        if (dto.getCryptographicBindingMethodsSupported() == null) {
            dto.setCryptographicBindingMethodsSupported(
                    CredentialConfigMetadataResolver.deriveBindingMethods(credentialConfig.getCredentialFormat(),
                            cryptographicBindingMethodsSupportedMap));
        }
        Map<String, Object> storedProofTypes = credentialConfig.getProofTypesSupported();
        dto.setProofTypesSupported(CredentialConfigMetadataResolver.resolveProofTypes(
                storedProofTypes == null || storedProofTypes.isEmpty() ? proofTypesSupported : storedProofTypes,
                proofTypesSupported));

        if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat()) && algs != null) {
            List<Object> coseAlgs = new ArrayList<>();
            for (String alg : algs) {
                coseAlgs.add(getCoseAlgorithm(alg));
            }
            dto.setCredentialSigningAlgValuesSupported(coseAlgs);
        } else {
            dto.setCredentialSigningAlgValuesSupported(algs != null ? new ArrayList<>(algs) : null);
        }
        return dto;
    }

    public Integer getCoseAlgorithm(String signAlgorithm) {
        if (signAlgorithm == null) {
            throw new IllegalArgumentException("Missing COSE signing algorithm");
        }
        Integer coseAlg = COSE_ALGORITHM_INTEGER_MAP.get(signAlgorithm);
        if (coseAlg == null) {
            throw new IllegalArgumentException("Unsupported COSE signing algorithm for mso_mdoc: " + signAlgorithm);
        }
        return coseAlg;
    }

    private void populateCommonMetadataFields(CredentialIssuerMetadataDTO metadata) {
        metadata.setCredentialIssuer(credentialIssuer);
        metadata.setAuthorizationServers(resolveAuthorizationServers());
        metadata.setCredentialEndpoint(buildCredentialEndpoint());
        metadata.setDisplay(issuerDisplay);
        if (allowCNonce) metadata.setNonceEndpoint(buildNonceEndpoint());
    }

    private String buildNonceEndpoint() {
        return credentialIssuer + servletPath + "/nonce";
    }

    private List<String> resolveAuthorizationServers() {
        Set<String> allServers = new LinkedHashSet<>();

        if (StringUtils.hasText(authUrl)) {
            Arrays.stream(authUrl.split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .forEach(allServers::add);
        }

        if (authorizationServerMapping != null) {
            authorizationServerMapping.values().stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .forEach(allServers::add);
        }

        return new ArrayList<>(allServers);
    }

    private String buildCredentialEndpoint() {
        return credentialIssuer + servletPath + "/issuance/credential";
    }

    private CredentialConfigurationSupportedDTO mapToSupportedDTO(CredentialConfig credentialConfig) {
        CredentialConfigurationSupportedDTO credentialConfigurationSupported = new CredentialConfigurationSupportedDTO();
        CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);
        credentialConfigurationSupported.setFormat(credentialConfigurationDTO.getCredentialFormat());
        credentialConfigurationSupported.setScope(credentialConfigurationDTO.getScope());
        credentialConfigurationSupported.setCryptographicBindingMethodsSupported(credentialConfig.getCryptographicBindingMethodsSupported());
        credentialConfigurationSupported.setProofTypesSupported(credentialConfig.getProofTypesSupported());

        CredentialMetadataDTO credentialMetadataDTO = new CredentialMetadataDTO();
        credentialMetadataDTO.setDisplay(credentialConfigurationDTO.getMetaDataDisplay());
        if (VCFormats.LDP_VC.equals(credentialConfig.getCredentialFormat())) {
            CredentialDefinition credentialDefinition = new CredentialDefinition();
            credentialDefinition.setType(credentialConfigurationDTO.getCredentialTypes());
            credentialDefinition.setContext(credentialConfigurationDTO.getContextURLs());
            credentialConfigurationSupported.setCredentialDefinition(credentialDefinition);
            credentialMetadataDTO.setClaims(mapStandardClaims(credentialConfig.getClaims()));
        } else if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            credentialConfigurationSupported.setDocType(credentialConfig.getDocType());
            credentialMetadataDTO.setClaims(mapMDocClaims(credentialConfig.getMsoMdocClaims()));
        } else if (VCFormats.DC_SD_JWT.equals(credentialConfig.getCredentialFormat())) {
            credentialConfigurationSupported.setVct(credentialConfig.getSdJwtVct());
            credentialMetadataDTO.setClaims(mapStandardClaims(credentialConfig.getSdJwtClaims()));
        }
        credentialConfigurationSupported.setCredentialMetadataDTO(credentialMetadataDTO);

        return credentialConfigurationSupported;
    }

    private List<CredentialMetadataDTO.Claims> mapStandardClaims(Map<String, Claims> claims) {
        if (claims == null) return Collections.emptyList();
        return claims.entrySet().stream()
                .map(entry -> buildClaimObject(Collections.singletonList(entry.getKey()), entry.getValue()))
                .collect(Collectors.toList());
    }

    private List<CredentialMetadataDTO.Claims> mapMDocClaims(Map<String, Map<String, Claims>> mDocClaims) {
        if (mDocClaims == null) return Collections.emptyList();
        return mDocClaims.entrySet().stream()
                .filter(namespace -> namespace.getValue() != null)
                .flatMap(namespace -> namespace.getValue().entrySet().stream()
                        .map(entry -> buildClaimObject(Arrays.asList(namespace.getKey(), entry.getKey()), entry.getValue())))
                .collect(Collectors.toList());
    }

    private CredentialMetadataDTO.Claims buildClaimObject(List<String> path, Claims value) {
        CredentialMetadataDTO.Claims claim = new CredentialMetadataDTO.Claims();
        claim.setPath(path);
        if (value != null) {
            if (value.getDisplay() != null) {
                List<ClaimsDisplayFieldsConfigDTO.Display> displayList = value.getDisplay().stream()
                        .map(d -> new ClaimsDisplayFieldsConfigDTO.Display(d.getName(), d.getLocale()))
                        .collect(Collectors.toList());
                claim.setDisplay(displayList);
            }
            claim.setMandatory(value.isMandatory());
        }
        return claim;
    }
}