package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.dto.CredentialConfigResponse;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialConfigurationSupportedDTO;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.mapper.CredentialConfigMapper;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialCacheKeyGenerator;
import io.mosip.certify.validators.credentialconfigvalidators.LdpVcCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.MsoMdocCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.SdJwtCredentialConfigValidator;
import org.checkerframework.checker.units.qual.C;
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
        credentialConfig.setCredentialSubject(Map.of("name", "Full Name"));
        credentialConfig.setKeyManagerAppId("TEST2019");

        credentialConfigurationDTO = new CredentialConfigurationDTO();
        credentialConfigurationDTO.setCredentialConfigKeyId("test-credential");
        credentialConfigurationDTO.setDisplay(List.of());
        credentialConfigurationDTO.setVcTemplate("test_template");
        credentialConfigurationDTO.setCredentialFormat("test_vc");
        credentialConfigurationDTO.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTO.setCredentialType(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTO.setCredentialSubject(Map.of("name", "Full Name"));

        ReflectionTestUtils.setField(credentialConfigurationService, "credentialIssuer", "http://example.com/");
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialIssuerDomainUrl", "http://example.com/");
        ReflectionTestUtils.setField(credentialConfigurationService, "authServers", List.of("http://auth.com"));
        ReflectionTestUtils.setField(credentialConfigurationService, "servletPath", "v1/test");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        ReflectionTestUtils.setField(credentialConfigurationService, "issuerDisplay", List.of(Map.of()));
    }

    @Test
    public void addNewCredentialConfig_Success() throws JsonProcessingException {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(credentialConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(credentialConfig);

        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.addCredentialConfiguration(credentialConfigurationDTO);

        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());
        Assert.assertEquals("active", credentialConfigResponse.getStatus());
    }

    @Test
    public void addCredentialConfiguration_DataProviderMode_VcTemplateNull_ThrowsException() throws Exception {
        // Arrange
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(null); // or ""

        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(new CredentialConfig());

        // Act & Assert
        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.addCredentialConfiguration(dto)
        );
        org.junit.Assert.assertEquals("Credential Template is mandatory for this `DataProvider` plugin issuer.", exception.getMessage());
    }

    @Test
    public void getCredentialConfigById_Success() throws JsonProcessingException {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findById(anyString())).thenReturn(optional);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);
        CredentialConfigurationDTO credentialConfigurationDTOResponse = credentialConfigurationService.getCredentialConfigurationById("test");

        Assert.assertNotNull(credentialConfigurationDTOResponse);
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialType());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialFormat());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getContext());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals("test_template", credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), credentialConfigurationDTOResponse.getContext());
        Assert.assertEquals(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"), credentialConfigurationDTOResponse.getCredentialType());
        Assert.assertEquals("test_vc", credentialConfigurationDTOResponse.getCredentialFormat());
    }

    @Test
    public void getCredentialConfigurationById_ConfigNotFound() {
        when(credentialConfigRepository.findById("12345678"))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("12345678"));

        assertEquals("Configuration not found with the provided id: " + "12345678", exception.getMessage());
    }

    @Test
    public void getCredentialConfigurationById_ConfigNotActive_ThrowsException() {
        CredentialConfig inactiveConfig = new CredentialConfig();
        inactiveConfig.setStatus("inactive"); // Not Constants.ACTIVE
        when(credentialConfigRepository.findById(anyString())).thenReturn(Optional.of(inactiveConfig));

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("test-id")
        );
        assertEquals("Configuration not active.", exception.getMessage());
    }

    @Test
    public void updateExistingCredentialConfig_Success() throws JsonProcessingException {

        CredentialConfig mockCredentialConfig = new CredentialConfig();
        String expectedId = "12345678";
        String expectedStatus = "active"; // This status should be what you expect after the "update"
        mockCredentialConfig.setConfigId(expectedId);
        mockCredentialConfig.setStatus(expectedStatus);

        Optional<CredentialConfig> optionalConfig = Optional.of(mockCredentialConfig);
        when(credentialConfigRepository.findById(eq(expectedId))).thenReturn(optionalConfig);


        CredentialConfigurationDTO mockDto = new CredentialConfigurationDTO(); // Dummy DTO for the mapper call
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));


        when(credentialConfigRepository.save(any(CredentialConfig.class)))
                .thenReturn(mockCredentialConfig); // Return the prepared mockCredentialConfig

        // --- Act ---
        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.updateCredentialConfiguration(expectedId, mockDto);

        // --- Assert ---
        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());

        Assert.assertEquals(expectedId, credentialConfigResponse.getId());
        Assert.assertEquals(expectedStatus, credentialConfigResponse.getStatus());

        // Verify interactions
        verify(credentialConfigRepository).findById(eq(expectedId));
        verify(credentialConfigMapper).updateEntityFromDto(eq(mockDto), eq(mockCredentialConfig));
        verify(credentialConfigRepository).save(eq(mockCredentialConfig));
    }

    @Test
    public void updateExistingCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findById(anyString()))
                .thenReturn(Optional.empty());

        CredentialConfigException exception = assertThrows(CredentialConfigException.class, () ->
                credentialConfigurationService.updateCredentialConfiguration("12345678", new CredentialConfigurationDTO()));

        assertEquals("Configuration not found with the provided id: " + "12345678", exception.getMessage());
    }

    @Test
    public void deleteCredentialConfig_Success() throws JsonProcessingException {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findById(anyString())).thenReturn(optional);
        doNothing().when(credentialConfigRepository).delete(any(CredentialConfig.class));
        String result = credentialConfigurationService.deleteCredentialConfigurationById("12345678");

        Assert.assertNotNull(result);
        assertEquals("12345678", result);
    }

    @Test
    public void deleteCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findById(anyString()))
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
        verify(credentialConfigMapper, never()).toDto(any());
    }

    @Test
    public void fetchCredentialIssuerMetadata_MsoMdocFormat() {
        // Setup CredentialConfig with MSO_MDOC format
        CredentialConfig mdocConfig = new CredentialConfig();
        mdocConfig.setConfigId(UUID.randomUUID().toString());
        mdocConfig.setCredentialConfigKeyId("mdoc-credential");

        mdocConfig.setStatus("active");
        mdocConfig.setCredentialFormat("mso_mdoc");
        mdocConfig.setClaims(Map.of("firstName", "First Name", "lastName", "Last Name"));
        mdocConfig.setDocType("docType1");

        List<CredentialConfig> credentialConfigList = List.of(mdocConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);

        // Setup DTO for MSO_MDOC
        CredentialConfigurationDTO mdocDTO = new CredentialConfigurationDTO();
        mdocDTO.setCredentialFormat("mso_mdoc");
        mdocDTO.setCredentialConfigKeyId("mdoc-credential");
        mdocDTO.setScope("mdoc_scope");
        mdocDTO.setClaims(Map.of("firstName", "First Name", "lastName", "Last Name"));
        mdocDTO.setDocType("docType1");

        when(credentialConfigMapper.toDto(mdocConfig)).thenReturn(mdocDTO);

        // Call the method
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("latest");

        // Verify MSO_MDOC configuration
        Assert.assertNotNull(result.getCredentialConfigurationSupportedDTO());
        Assert.assertEquals(1, result.getCredentialConfigurationSupportedDTO().size());

        CredentialConfigurationSupportedDTO supportedDTO = result.getCredentialConfigurationSupportedDTO().get("mdoc-credential");
        Assert.assertNotNull(supportedDTO);
        Assert.assertEquals("mso_mdoc", supportedDTO.getFormat());
        Assert.assertNotNull(supportedDTO.getClaims());
        Assert.assertEquals("docType1", supportedDTO.getDocType());
        Assert.assertNull(supportedDTO.getCredentialDefinition());
    }

    // Add these methods to CredentialConfigurationServiceImplTest

    @Test
    public void addNewCredentialConfig_MsoMdoc_Success() throws JsonProcessingException {
        CredentialConfig mdocConfig = new CredentialConfig();
        mdocConfig.setConfigId(UUID.randomUUID().toString());
        mdocConfig.setCredentialConfigKeyId("mdoc-credential");
        mdocConfig.setStatus("active");
        mdocConfig.setVcTemplate("mdoc_template");
        mdocConfig.setCredentialFormat("mso_mdoc");
        mdocConfig.setDocType("docType1");

        CredentialConfigurationDTO mdocDTO = new CredentialConfigurationDTO();
        mdocDTO.setCredentialFormat("mso_mdoc");
        mdocDTO.setCredentialConfigKeyId("mdoc-credential");
        mdocDTO.setDocType("docType1");

        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(mdocConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(mdocConfig);

        // Mock validator static methods if needed, or ensure they return true/false as per your setup

        CredentialConfigResponse response = credentialConfigurationService.addCredentialConfiguration(mdocDTO);

        Assert.assertNotNull(response);
        Assert.assertEquals("active", response.getStatus());
        Assert.assertEquals(mdocConfig.getConfigId(), response.getId());
    }

    @Test
    public void addNewCredentialConfig_SdJwt_Success() throws JsonProcessingException {
        CredentialConfig sdJwtConfig = new CredentialConfig();
        sdJwtConfig.setConfigId(UUID.randomUUID().toString());
        sdJwtConfig.setCredentialConfigKeyId("sdjwt-credential");
        sdJwtConfig.setVcTemplate("sd_jwt_template");
        sdJwtConfig.setStatus("active");
        sdJwtConfig.setCredentialFormat("vc+sd-jwt");
        sdJwtConfig.setSdJwtVct("test-vct");

        CredentialConfigurationDTO sdJwtDTO = new CredentialConfigurationDTO();
        sdJwtDTO.setCredentialFormat("vc+sd-jwt");
        sdJwtDTO.setCredentialConfigKeyId("sdjwt-credential");

        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(sdJwtConfig);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(sdJwtConfig);

        // Mock validator static methods if needed, or ensure they return true/false as per your setup

        CredentialConfigResponse response = credentialConfigurationService.addCredentialConfiguration(sdJwtDTO);

        Assert.assertNotNull(response);
        Assert.assertEquals("active", response.getStatus());
        Assert.assertEquals(sdJwtConfig.getConfigId(), response.getId());
    }

    @Test
    public void validateCredentialConfiguration_LdpVc_Invalid_ThrowsException() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("ldp_vc");
        // Simulate invalid config
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(config)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", config)
            );
            assertEquals("Context and credentialType are mandatory for ldp_vc format", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_LdpVc_Duplicate_ThrowsException() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("ldp_vc");
        try (var mocked = org.mockito.Mockito.mockStatic(LdpVcCredentialConfigValidator.class)) {
            mocked.when(() -> LdpVcCredentialConfigValidator.isValidCheck(config)).thenReturn(true);
            mocked.when(() -> LdpVcCredentialConfigValidator.isConfigAlreadyPresent(eq(config), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", config)
            );
            assertEquals("Configuration already exists for the given context and credentialType", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_MsoMdoc_Invalid_ThrowsException() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("mso_mdoc");
        try (var mocked = org.mockito.Mockito.mockStatic(MsoMdocCredentialConfigValidator.class)) {
            mocked.when(() -> MsoMdocCredentialConfigValidator.isValidCheck(config)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", config)
            );
            assertEquals("Doctype field is mandatory for mso_mdoc", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_MsoMdoc_Duplicate_ThrowsException() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("mso_mdoc");
        try (var mocked = org.mockito.Mockito.mockStatic(MsoMdocCredentialConfigValidator.class)) {
            mocked.when(() -> MsoMdocCredentialConfigValidator.isValidCheck(config)).thenReturn(true);
            mocked.when(() -> MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(eq(config), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", config)
            );
            assertEquals("Configuration already exists for the given doctype", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_SdJwt_Invalid_ThrowsException() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("vc+sd-jwt");
        try (var mocked = org.mockito.Mockito.mockStatic(SdJwtCredentialConfigValidator.class)) {
            mocked.when(() -> SdJwtCredentialConfigValidator.isValidCheck(config)).thenReturn(false);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", config)
            );
            assertEquals("Vct field is mandatory for vc+sd-jwt", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_SdJwt_Duplicate_ThrowsException() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("vc+sd-jwt");
        try (var mocked = org.mockito.Mockito.mockStatic(SdJwtCredentialConfigValidator.class)) {
            mocked.when(() -> SdJwtCredentialConfigValidator.isValidCheck(config)).thenReturn(true);
            mocked.when(() -> SdJwtCredentialConfigValidator.isConfigAlreadyPresent(eq(config), any())).thenReturn(true);
            CertifyException ex = assertThrows(CertifyException.class, () ->
                    ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", config)
            );
            assertEquals("Configuration already exists for the given vct", ex.getMessage());
        }
    }

    @Test
    public void validateCredentialConfiguration_UnsupportedFormat_ThrowsException() {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat("unsupported_format");
        CertifyException ex = assertThrows(CertifyException.class, () ->
                ReflectionTestUtils.invokeMethod(credentialConfigurationService, "validateCredentialConfiguration", config)
        );
        assertEquals("Unsupported format: unsupported_format", ex.getMessage());
    }
}
