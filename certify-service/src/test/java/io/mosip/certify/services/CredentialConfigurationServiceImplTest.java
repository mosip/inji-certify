package io.mosip.certify.services;

import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.attributes.ClaimsDisplayFieldsConfigs;
import io.mosip.certify.entity.attributes.CredentialSubjectParameters;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import io.mosip.certify.validators.credentialconfigvalidators.LdpVcCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.MsoMdocCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.SdJwtCredentialConfigValidator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialConfigurationServiceImplTest {

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @Mock
    private CredentialConfigMapper credentialConfigMapper;

    @InjectMocks
    private CredentialConfigurationServiceImpl credentialConfigurationService;

    @Mock
    private CredentialConfigurationDTO credentialConfigurationDTO;

    @Mock
    private CredentialConfig credentialConfig;

    @Before
    public void setup() {
        Map<String, List<List<String>>> keyAliasMapper = new HashMap<>();
        keyAliasMapper.put("EdDSA", List.of(
                List.of("TEST2019", "TEST2019-REF")));
//        keyAliasMapper.put("RS256", List.of());

        MockitoAnnotations.openMocks(this);
        credentialConfig = new CredentialConfig();
        String id = UUID.randomUUID().toString();
        credentialConfig.setConfigId(id);
        credentialConfig.setCredentialConfigKeyId("test-credential");
        credentialConfig.setStatus("active");
        credentialConfig.setVcTemplate("test_template");
        credentialConfig.setContext("https://www.w3.org/2018/credentials/v1");
        credentialConfig.setCredentialType("VerifiableCredential,TestVerifiableCredential");
        credentialConfig.setCredentialFormat("ldp_vc");
        credentialConfig.setDidUrl("did:web:test.github.io:test-env:test-folder");
        credentialConfig.setOrder(Arrays.asList("test1", "test2", "test3", "test4"));
        credentialConfig.setScope("test_vc_ldp");
        credentialConfig.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        credentialConfig.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        credentialConfig.setCredentialSubject(Map.of("name", new CredentialSubjectParameters(List.of(new CredentialSubjectParameters.Display("Full Name", "en")))));
        credentialConfig.setKeyManagerAppId("TEST2019");
        credentialConfig.setKeyManagerRefId("TEST2019-REF");
        credentialConfig.setSignatureCryptoSuite("Ed25519Signature2020");

        credentialConfigurationDTO = new CredentialConfigurationDTO();
        credentialConfigurationDTO.setCredentialConfigKeyId("test-credential");
        credentialConfigurationDTO.setMetaDataDisplay(List.of());
        credentialConfigurationDTO.setVcTemplate("test_template");
        credentialConfigurationDTO.setCredentialFormat("ldp_vc");
        credentialConfigurationDTO.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTO.setCredentialTypes(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTO.setSignatureCryptoSuite("Ed25519Signature2020");
        credentialConfigurationDTO.setKeyManagerAppId("TEST2019");
        credentialConfigurationDTO.setKeyManagerRefId("TEST2019-REF");
        credentialConfigurationDTO.setCredentialSubjectDefinition(Map.of("name", new CredentialSubjectParametersDTO(List.of(new CredentialSubjectParametersDTO.Display("Full Name", "en")))));

        ReflectionTestUtils.setField(credentialConfigurationService, "credentialIssuer", "http://example.com/");
        ReflectionTestUtils.setField(credentialConfigurationService, "authUrl", "http://auth.com");
        ReflectionTestUtils.setField(credentialConfigurationService, "servletPath", "v1/test");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        ReflectionTestUtils.setField(credentialConfigurationService, "issuerDisplay", List.of(Map.of()));
        Map<String, List<String>> credentialSigningMap = new LinkedHashMap<>();
        credentialSigningMap.put("Ed25519Signature2020", List.of("EdDSA"));
        credentialSigningMap.put("RsaSignature2018", List.of("RS256"));
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap", new LinkedHashMap<>());
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", credentialSigningMap);
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", new LinkedHashMap<>());
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", keyAliasMapper);
    }

    @Test
    public void addNewCredentialConfig_Success() {
        credentialConfigurationDTO.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTO.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTO.setSignatureCryptoSuite("Ed25519Signature2020");
        credentialConfigurationDTO.setSignatureAlgo("EdDSA");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(credentialConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(credentialConfig);

        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.addCredentialConfiguration(credentialConfigurationDTO);

        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());
        Assert.assertEquals("active", credentialConfigResponse.getStatus());
    }

    @Test
    public void addCredentialConfiguration_DataProviderMode_VcTemplateNull_ThrowsException() {
        // Arrange
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(null); // or ""

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfiguration(dto)
        );
        org.junit.Assert.assertEquals("Credential Template is mandatory for the DataProvider plugin issuer.", exception.getMessage());
    }

    @Test
    public void getCredentialConfigById_Success() {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString())).thenReturn(optional);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);
        CredentialConfigurationDTO credentialConfigurationDTOResponse = credentialConfigurationService.getCredentialConfigurationById("test");

        Assert.assertNotNull(credentialConfigurationDTOResponse);
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialTypes());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialFormat());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getContextURLs());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals("test_template", credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), credentialConfigurationDTOResponse.getContextURLs());
        Assert.assertEquals(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"), credentialConfigurationDTOResponse.getCredentialTypes());
        Assert.assertEquals("ldp_vc", credentialConfigurationDTOResponse.getCredentialFormat());
    }

    @Test
    public void getCredentialConfigurationById_ConfigNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId("12345678"))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("12345678"));

        assertEquals("Configuration not found with the provided id: " + "12345678", exception.getMessage());
    }

    @Test
    public void getCredentialConfigurationById_ConfigNotActive_ThrowsException() {
        CredentialConfig inactiveConfig = new CredentialConfig();
        inactiveConfig.setStatus("inactive"); // Not Constants.ACTIVE
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString())).thenReturn(Optional.of(inactiveConfig));
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("test-id")
        );
        assertEquals("Configuration not active.", exception.getMessage());
    }

    @Test
    public void updateExistingCredentialConfig_Success() {
        CredentialConfig mockCredentialConfig = new CredentialConfig();
        String expectedId = "test-credential";
        String expectedStatus = "active";
        mockCredentialConfig.setConfigId("12345678");
        mockCredentialConfig.setCredentialConfigKeyId("test-credential");
        mockCredentialConfig.setStatus(expectedStatus);
        mockCredentialConfig.setVcTemplate("some_template");
        mockCredentialConfig.setCredentialFormat("vc+sd-jwt");
        mockCredentialConfig.setSdJwtVct("test-vct");
        mockCredentialConfig.setSignatureAlgo("ES256");


        Optional<CredentialConfig> optionalConfig = Optional.of(mockCredentialConfig);
        when(credentialConfigRepository.findByCredentialConfigKeyId(eq(expectedId))).thenReturn(optionalConfig);


        CredentialConfigurationDTO mockDto = new CredentialConfigurationDTO();

        // Create a valid DTO for validation that will be returned by toDto
        CredentialConfigurationDTO validationDto = new CredentialConfigurationDTO();
        validationDto.setCredentialFormat("vc+sd-jwt");
        validationDto.setVcTemplate("some_template");
        validationDto.setSdJwtVct("test-vct");
        validationDto.setSignatureAlgo("ES256");
        validationDto.setCredentialConfigKeyId("test-credential");
        validationDto.setCredentialStatusPurposes(null); // Ensure this is not null to avoid NPE

        // Mock the mapper methods
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(validationDto);
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(mockCredentialConfig);

        // --- Act ---
        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.updateCredentialConfiguration(expectedId, mockDto);

        // --- Assert ---
        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());

        Assert.assertEquals(expectedId, credentialConfigResponse.getId());
        Assert.assertEquals(expectedStatus, credentialConfigResponse.getStatus());

        // Verify interactions
        verify(credentialConfigRepository).findByCredentialConfigKeyId(eq(expectedId));
        verify(credentialConfigMapper).updateEntityFromDto(eq(mockDto), eq(mockCredentialConfig));
        verify(credentialConfigRepository).save(eq(mockCredentialConfig));
    }

    @Test
    public void updateExistingCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString()))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.updateCredentialConfiguration("12345678", new CredentialConfigurationDTO()));

        assertEquals("Configuration not found with the provided id: " + "12345678", exception.getMessage());
    }

    @Test
    public void deleteCredentialConfig_Success() {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString())).thenReturn(optional);
        doNothing().when(credentialConfigRepository).delete(any(CredentialConfig.class));
        String result = credentialConfigurationService.deleteCredentialConfigurationById("12345678");

        Assert.assertNotNull(result);
        assertEquals("12345678", result);
    }

    @Test
    public void deleteCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString()))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.deleteCredentialConfigurationById("12345678"));

        assertEquals("Configuration not found with the provided id: 12345678", exception.getMessage());
    }

    @Test
    public void fetchCredentialIssuerMetadata_Success() {
        // Setup test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);

        // Call the method
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        // Verify results
        Assert.assertNotNull(result);
        Assert.assertEquals("http://example.com/", result.getCredentialIssuer());
        Assert.assertEquals(List.of("http://auth.com"), result.getAuthorizationServers());
        Assert.assertEquals("http://example.com/v1/test/issuance/credential", result.getCredentialEndpoint());

        // Verify credential configuration
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTO());
        Assert.assertEquals(1, result.getCredentialConfigurationSupportedDTO().size());
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTO().containsKey("test-credential"));

        // Verify mapping was called
        verify(credentialConfigRepository).findAll();
        verify(credentialConfigMapper).toDto(credentialConfig);
    }

    @Test
    public void fetchCredentialIssuerMetadata_SigningAlgValuesSupported_UsesSignatureAlgo_WhenCryptoSuiteIsNull() {
        CredentialConfig config = new CredentialConfig();
        config.setConfigId(UUID.randomUUID().toString());
        config.setCredentialConfigKeyId("test-credential");
        config.setStatus("active");
        config.setCredentialFormat("ldp_vc");
        config.setSignatureCryptoSuite(null); // triggers else branch
        config.setSignatureAlgo("ES256");
        config.setCredentialSubject(null);

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        when(credentialConfigMapper.toDto(config)).thenReturn(dto);


        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        Assert.assertNotNull(result);
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTO().containsKey("test-credential"));
        CredentialConfigurationSupportedDTO supportedDTO = result.getCredentialConfigurationSupportedDTO().get("test-credential");
        Assert.assertEquals(List.of("ES256"), supportedDTO.getCredentialSigningAlgValuesSupported());
    }

    @Test
    public void fetchCredentialIssuerMetadata_SigningAlgValuesSupported_UsesSignatureAlgo_WhenCryptoSuiteIsNull_SdJwtFormat() {
        CredentialConfig config = new CredentialConfig();
        config.setConfigId(UUID.randomUUID().toString());
        config.setCredentialConfigKeyId("sdjwt-credential");
        config.setStatus("active");
        config.setCredentialFormat("vc+sd-jwt");
        config.setSignatureCryptoSuite(null); // triggers else branch
        config.setSignatureAlgo("ES256");
        config.setSdJwtVct("test-vct");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(config));
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("vc+sd-jwt");
        when(credentialConfigMapper.toDto(config)).thenReturn(dto);

        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        Assert.assertNotNull(result);
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTO().containsKey("sdjwt-credential"));
        CredentialConfigurationSupportedDTO supportedDTO = result.getCredentialConfigurationSupportedDTO().get("sdjwt-credential");
        Assert.assertEquals(List.of("ES256"), supportedDTO.getCredentialSigningAlgValuesSupported());
    }

    @Test
    public void fetchCredentialIssuerMetadata_vd11Version() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);

        // Call with specific version
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("vd11");

        // Verify version in endpoint
        Assert.assertEquals("http://example.com/v1/test/issuance/vd11/credential", result.getCredentialEndpoint());
    }

    @Test
    public void fetchCredentialIssuerMetadata_vd12Version() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);

        // Call with specific version
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("vd12");

        // Verify version in endpoint
        Assert.assertEquals("http://example.com/v1/test/issuance/vd12/credential", result.getCredentialEndpoint());
    }

    @Test
    public void fetchCredentialIssuerMetadata_invalidVersion() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);

        // Call with specific version

        CertifyException ex = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.fetchCredentialIssuerMetadata("unsupported_version")
        );
        assertEquals("Unsupported version: unsupported_version", ex.getMessage());
    }

    @Test
    public void fetchCredentialIssuerMetadata_EmptyCredentialConfigs() {
        // Setup empty credential config list
        when(credentialConfigRepository.findAll()).thenReturn(Collections.emptyList());

        // Call the method
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        // Verify core metadata still populated
        Assert.assertNotNull(result);
        Assert.assertEquals("http://example.com/", result.getCredentialIssuer());
        Assert.assertEquals(List.of("http://auth.com"), result.getAuthorizationServers());

        // Verify empty configurations map
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTO());
        Assert.assertTrue(result.getCredentialConfigurationSupportedDTO().isEmpty());

        // Verify no mapping calls
        verify(credentialConfigRepository).findAll();
        verify(credentialConfigMapper, never()).toDto((CredentialConfig) any());
    }

    @Test
    public void fetchCredentialIssuerMetadata_MsoMdocFormat() {
        // Setup CredentialConfig with MSO_MDOC format
        CredentialConfig mdocConfig = new CredentialConfig();
        mdocConfig.setConfigId(UUID.randomUUID().toString());
        mdocConfig.setCredentialConfigKeyId("mdoc-credential");

        mdocConfig.setStatus("active");
        mdocConfig.setCredentialFormat("mso_mdoc");
        mdocConfig.setMsoMdocClaims(Map.of("firstName", Map.of( "First Name", new ClaimsDisplayFieldsConfigs(List.of(new ClaimsDisplayFieldsConfigs.Display("Test","en"))))));
        mdocConfig.setDocType("docType1");

        List<CredentialConfig> credentialConfigList = List.of(mdocConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);

        // Setup DTO for MSO_MDOC
        CredentialConfigurationDTO mdocDTO = new CredentialConfigurationDTO();
        mdocDTO.setCredentialFormat("mso_mdoc");
        mdocDTO.setCredentialConfigKeyId("mdoc-credential");
        mdocDTO.setScope("mdoc_scope");
        mdocDTO.setMsoMdocClaims(Map.of("firstName", Map.of( "First Name", new ClaimsDisplayFieldsConfigDTO(List.of(new ClaimsDisplayFieldsConfigDTO.Display("Test","en"))))));
        mdocDTO.setDocType("docType1");

        when(credentialConfigMapper.toDto(mdocConfig)).thenReturn(mdocDTO);

        // Call the method
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        // Verify MSO_MDOC configuration
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTO());
        Assert.assertEquals(1, result.getCredentialConfigurationSupportedDTO().size());
        Assert.assertEquals(Map.of("firstName", Map.of( "First Name", new ClaimsDisplayFieldsConfigs(List.of(new ClaimsDisplayFieldsConfigs.Display("Test","en"))))), result.getCredentialConfigurationSupportedDTO().get("mdoc-credential").getClaims());

        CredentialConfigurationSupportedDTO supportedDTO = result.getCredentialConfigurationSupportedDTO().get("mdoc-credential");
        Assert.assertNotNull(supportedDTO);
        Assert.assertEquals("mso_mdoc", supportedDTO.getFormat());
        Assert.assertNotNull(supportedDTO.getClaims());
        Assert.assertEquals("docType1", supportedDTO.getDocType());
        Assert.assertNull(supportedDTO.getCredentialDefinition());
    }

    // Add these methods to CredentialConfigurationServiceImplTest

    @Test
    public void addNewCredentialConfig_MsoMdoc_Success(){
        CredentialConfig mdocConfig = new CredentialConfig();
        mdocConfig.setConfigId(UUID.randomUUID().toString());
        mdocConfig.setCredentialConfigKeyId("mdoc-credential");
        mdocConfig.setStatus("active");
        mdocConfig.setVcTemplate("mdoc_template");
        mdocConfig.setCredentialFormat("mso_mdoc");
        mdocConfig.setDocType("docType1");
        mdocConfig.setSignatureCryptoSuite("Ed25519Signature2020");

        CredentialConfigurationDTO mdocDTO = new CredentialConfigurationDTO();
        mdocDTO.setCredentialFormat("mso_mdoc");
        mdocDTO.setCredentialConfigKeyId("mdoc-credential");
        mdocDTO.setDocType("docType1");
        mdocDTO.setVcTemplate("mdoc_template");
        mdocDTO.setSignatureCryptoSuite("Ed25519Signature2020"); // required

        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(mdocConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(mdocConfig);

        CredentialConfigResponse response = credentialConfigurationService.addCredentialConfiguration(mdocDTO);

        Assert.assertNotNull(response);
        Assert.assertEquals("active", response.getStatus());
        Assert.assertEquals(mdocConfig.getCredentialConfigKeyId(), response.getId());
    }

    @Test
    public void addNewCredentialConfig_SdJwt_Success() {
        CredentialConfig sdJwtConfig = new CredentialConfig();
        sdJwtConfig.setConfigId(UUID.randomUUID().toString());
        sdJwtConfig.setCredentialConfigKeyId("sdjwt-credential");
        sdJwtConfig.setVcTemplate("sd_jwt_template");
        sdJwtConfig.setStatus("active");
        sdJwtConfig.setCredentialFormat("vc+sd-jwt");
        sdJwtConfig.setSdJwtVct("test-vct");
        sdJwtConfig.setSignatureAlgo("ES256");

        CredentialConfigurationDTO sdJwtDTO = new CredentialConfigurationDTO();
        sdJwtDTO.setCredentialFormat("vc+sd-jwt");
        sdJwtDTO.setCredentialConfigKeyId("sdjwt-credential");
        sdJwtDTO.setVcTemplate("sd_jwt_template");
        sdJwtDTO.setSdJwtVct("test-vct"); // required
        sdJwtDTO.setSignatureAlgo("ES256"); // required

        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(sdJwtConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(sdJwtConfig);


        CredentialConfigResponse response = credentialConfigurationService.addCredentialConfiguration(sdJwtDTO);

        Assert.assertNotNull(response);
        Assert.assertEquals("active", response.getStatus());
        Assert.assertEquals(sdJwtConfig.getCredentialConfigKeyId(), response.getId());
    }

    @Test
    public void validateCredentialConfiguration_LdpVc_Invalid_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Context, credentialType and signatureCryptoSuite are mandatory for ldp_vc format", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_LdpVc_Duplicate_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            mocked.when(() -> LdpVcCredentialConfigValidator.isConfigAlreadyPresent(eq(dto), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Configuration already exists for the given context and credentialType", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_MsoMdoc_Invalid_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(MsoMdocCredentialConfigValidator.class)) {
            mocked.when(() -> MsoMdocCredentialConfigValidator.isValidCheck(dto)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Doctype and signatureCryptoSuite fields are mandatory for mso_mdoc format", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_MsoMdoc_Duplicate_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("mso_mdoc");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(MsoMdocCredentialConfigValidator.class)) {
            mocked.when(() -> MsoMdocCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            mocked.when(() -> MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(eq(dto), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Configuration already exists for the given doctype", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_SdJwt_Invalid_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("vc+sd-jwt");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(SdJwtCredentialConfigValidator.class)) {
            mocked.when(() -> SdJwtCredentialConfigValidator.isValidCheck(dto)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Vct and signatureAlgo fields are mandatory for vc+sd-jwt format", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_SdJwt_Duplicate_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("vc+sd-jwt");
        dto.setVcTemplate("test_template");
        try (var mocked = org.mockito.Mockito.mockStatic(SdJwtCredentialConfigValidator.class)) {
            mocked.when(() -> SdJwtCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            mocked.when(() -> SdJwtCredentialConfigValidator.isConfigAlreadyPresent(eq(dto), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Configuration already exists for the given vct", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_LdpVc_MissingSignatureAlgo_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setSignatureCryptoSuite("test-rdfc-2019");
        dto.setSignatureAlgo("");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            mocked.when(() -> LdpVcCredentialConfigValidator.isConfigAlreadyPresent(eq(dto), any())).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
            );
            assertEquals("Unsupported signature crypto suite: test-rdfc-2019", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_MultipleCredentialStatusPurposes_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(List.of("purpose1", "purpose2"));
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1"));
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
        );
        assertEquals("Multiple credential status purposes are not currently supported.", ex.getMessage());
    }

    @Test
    public void validateCredentialConfiguration_InvalidCredentialStatusPurpose_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(List.of("invalid_purpose"));
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true)
        );
        assertEquals("Invalid credential status purposes. Allowed values are: [purpose1, purpose2]", ex.getMessage());
    }

    @Test
    public void validateCredentialConfiguration_NullCredentialStatusPurposes_AllowsConfig() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(null);
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true);
        }
    }

    @Test
    public void validateCredentialConfiguration_EmptyCredentialStatusPurposes_AllowsConfig() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(Collections.emptyList());
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true);
        }
    }

    @Test
    public void validateCredentialConfiguration_ValidSingleCredentialStatusPurpose_Succeeds() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate("test_template");
        dto.setCredentialStatusPurposes(List.of("purpose1"));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        ReflectionTestUtils.setField(credentialConfigurationService, "allowedCredentialStatusPurposes", List.of("purpose1", "purpose2"));
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(dto)).thenReturn(true);
            ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", dto, true);
        }
    }

    @Test
    public void validateKeyAliasMapperConfiguration_KeyAliasListIsNull_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc"); // Required to avoid NPE in switch statement
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        dto.setSignatureCryptoSuite("RsaSignature2018");
        dto.setSignatureAlgo("RS256");
        dto.setVcTemplate("test_template");

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfiguration(dto)
        );
        assertEquals("No key chooser configuration found for the signatureAlgo: RsaSignature2018", exception.getMessage());
    }

    @Test
    public void validateKeyAliasMpperConfiguration_NoMatchingAppIdAndRefId_ThrowsException() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc"); // Required to avoid NPE in switch statement
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("appId");
        dto.setKeyManagerRefId("refId");
        dto.setVcTemplate("test_template");

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfiguration(dto)
        );
        assertEquals("No matching appId and refId found in the key chooser list.", exception.getMessage());
    }
}
