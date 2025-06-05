package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.dto.CredentialConfigResponse;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialConfigurationSupportedDTO;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.mapper.CredentialConfigMapper;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialCacheKeyGenerator;
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
    public void getCredentialConfigById_Success() throws JsonProcessingException {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findByConfigId(anyString())).thenReturn(optional);
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
        when(credentialConfigRepository.findByConfigId("12345678"))
                .thenReturn(Optional.empty());

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("12345678"));

        assertEquals("Configuration not found with the provided id: " + "12345678", exception.getMessage());
    }

    @Test
    public void updateExistingCredentialConfig_Success() throws JsonProcessingException {

        CredentialConfig mockCredentialConfig = new CredentialConfig();
        String expectedId = "12345678";
        String expectedStatus = "active"; // This status should be what you expect after the "update"
        mockCredentialConfig.setConfigId(expectedId);
        mockCredentialConfig.setStatus(expectedStatus);

        Optional<CredentialConfig> optionalConfig = Optional.of(mockCredentialConfig);
        when(credentialConfigRepository.findByConfigId(eq(expectedId))).thenReturn(optionalConfig);


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
        verify(credentialConfigRepository).findByConfigId(eq(expectedId));
        verify(credentialConfigMapper).updateEntityFromDto(eq(mockDto), eq(mockCredentialConfig));
        verify(credentialConfigRepository).save(eq(mockCredentialConfig));
    }

    @Test
    public void updateExistingCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findByConfigId(anyString()))
                .thenReturn(Optional.empty());

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.updateCredentialConfiguration("12345678", new CredentialConfigurationDTO()));

        assertEquals("Configuration not found with the provided id: " + "12345678", exception.getMessage());
    }

    @Test
    public void deleteCredentialConfig_Success() throws JsonProcessingException {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findByConfigId(anyString())).thenReturn(optional);
        doNothing().when(credentialConfigRepository).delete(any(CredentialConfig.class));
        String result = credentialConfigurationService.deleteCredentialConfigurationById("12345678");

        Assert.assertNotNull(result);
        assertEquals("12345678", result);
    }

    @Test
    public void deleteCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findByConfigId(anyString()))
                .thenReturn(Optional.empty());

        CertifyException exception = assertThrows(CertifyException.class, () ->
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
    public void fetchCredentialIssuerMetadata_SpecificVersion() {
        // Setup minimal test data
        List<CredentialConfig> credentialConfigList = List.of(credentialConfig);
        when(credentialConfigRepository.findAll()).thenReturn(credentialConfigList);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(credentialConfigurationDTO);
//        when(credentialConfigurationDTO.getCredentialConfigKeyId()).thenReturn("test-credential");

        // Call with specific version
        CredentialIssuerMetadataDTO result = credentialConfigurationService.fetchCredentialIssuerMetadata("vd11");

        // Verify version in endpoint
        Assert.assertEquals("http://example.com/v1/test/issuance/vd11/credential", result.getCredentialEndpoint());
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
}
