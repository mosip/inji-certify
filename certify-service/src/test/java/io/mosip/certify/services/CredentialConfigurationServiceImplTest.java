package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.CredentialConfigResponse;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialConfigurationServiceImplTest {
    @Mock
    ObjectMapper objectMapper;

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @InjectMocks
    private CredentialConfigurationServiceImpl credentialConfigurationService;

    @Mock
    private CredentialConfigurationDTO credentialConfigurationDTO;

    @Mock
    private CredentialConfig credentialConfig;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        credentialConfigurationDTO = new CredentialConfigurationDTO();
        credentialConfigurationDTO.setVcTemplate("test_template");
        credentialConfigurationDTO.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTO.setCredentialType(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTO.setCredentialFormat("ldp_vc");
        credentialConfigurationDTO.setDidUrl("did:web:test.github.io:test-env:test-folder");
        credentialConfigurationDTO.setOrder(Arrays.asList("test1", "test2", "test3", "test4"));
        credentialConfigurationDTO.setScope("test_vc_ldp");
        credentialConfigurationDTO.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        credentialConfigurationDTO.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));

        credentialConfig = new CredentialConfig();
        String id = UUID.randomUUID().toString();
        credentialConfig.setId(id);
        credentialConfig.setStatus("active");
        credentialConfig.setConfiguration("test-config-string");
        credentialConfig.setCreatedTime(LocalDateTime.now());
    }

    @Test
    public void addNewCredentialConfig_Success() throws JsonProcessingException {
        when(objectMapper.writeValueAsString(any(CredentialConfigurationDTO.class)))
                .thenReturn("test-config-string");
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(credentialConfig);

        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.addCredentialConfiguration(credentialConfigurationDTO);

        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());
        Assert.assertEquals("active", credentialConfigResponse.getStatus());
    }


    @Test
    public void addCredentialConfiguration_JsonProcessingException() throws JsonProcessingException {
        when(objectMapper.writeValueAsString(any(CredentialConfigurationDTO.class)))
                .thenThrow(new JsonProcessingException("Error processing JSON") {});

        assertThrows(JsonProcessingException.class, () ->
                credentialConfigurationService.addCredentialConfiguration(credentialConfigurationDTO));

        verify(objectMapper).writeValueAsString(credentialConfigurationDTO);
        verify(credentialConfigRepository, never()).save(any());
    }

    @Test
    public void getCredentialConfigById_Success() throws JsonProcessingException {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findById(anyString())).thenReturn(optional);
        when(objectMapper.readValue("test-config-string", CredentialConfigurationDTO.class))
                .thenReturn(credentialConfigurationDTO);

        CredentialConfigurationDTO credentialConfigurationDTOResponse = credentialConfigurationService.getCredentialConfigurationById("test");

        Assert.assertNotNull(credentialConfigurationDTOResponse);
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialType());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getCredentialFormat());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getContext());
        Assert.assertNotNull(credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals("test_template", credentialConfigurationDTOResponse.getVcTemplate());
        Assert.assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), credentialConfigurationDTOResponse.getContext());
        Assert.assertEquals(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"), credentialConfigurationDTOResponse.getCredentialType());
        Assert.assertEquals("ldp_vc", credentialConfigurationDTOResponse.getCredentialFormat());
    }

    @Test
    public void getCredentialConfigurationById_ConfigNotFound() {
        when(credentialConfigRepository.findById("12345678"))
                .thenReturn(Optional.empty());

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("12345678"));

        assertEquals("Configuration not found with the provided id: " + "12345678", exception.getMessage());
    }

    @Test
    public void getCredentialConfigurationById_JsonProcessingException() throws JsonProcessingException {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findById("12345678"))
                .thenReturn(optional);

        when(objectMapper.readValue(anyString(), eq(CredentialConfigurationDTO.class)))
                .thenThrow(new JsonProcessingException("Error processing JSON") {});

        assertThrows(JsonProcessingException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("12345678"));
    }

    @Test
    public void updateExistingCredentialConfig_Success() throws JsonProcessingException {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findById(anyString())).thenReturn(optional);
        when(objectMapper.writeValueAsString(any(CredentialConfigurationDTO.class)))
                .thenReturn("test-config-string");

        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.updateCredentialConfiguration("12345678", credentialConfigurationDTO);

        Assert.assertNotNull(credentialConfigResponse);
        Assert.assertNotNull(credentialConfigResponse.getId());
        Assert.assertNotNull(credentialConfigResponse.getStatus());
        Assert.assertEquals("active", credentialConfigResponse.getStatus());
    }

    @Test
    public void updateExistingCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findById(anyString()))
                .thenReturn(Optional.empty());

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.getCredentialConfigurationById("12345678"));

        assertEquals("Configuration not found with the provided id: " + "12345678", exception.getMessage());
    }

    @Test
    public void updateExistingCredentialConfiguration_JsonProcessingException() throws JsonProcessingException {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findById("12345678"))
                .thenReturn(optional);

        when(objectMapper.writeValueAsString(any(CredentialConfigurationDTO.class)))
                .thenThrow(new JsonProcessingException("Error processing JSON") {});

        assertThrows(JsonProcessingException.class, () ->
                credentialConfigurationService.updateCredentialConfiguration("12345678", credentialConfigurationDTO));
    }

    @Test
    public void deleteCredentialConfig_Success() throws JsonProcessingException {
        Optional<CredentialConfig> optional = Optional.of(credentialConfig);
        when(credentialConfigRepository.findById(anyString())).thenReturn(optional);
        doNothing().when(credentialConfigRepository).deleteById(anyString());

        String result = credentialConfigurationService.deleteCredentialConfigurationById("12345678");

        Assert.assertNotNull(result);
        assertEquals("Configuration deleted with id: " + "12345678", result);
    }

    @Test
    public void deleteCredentialConfiguration_ConfigNotFound() {
        when(credentialConfigRepository.findById(anyString()))
                .thenReturn(Optional.empty());

        CertifyException exception = assertThrows(CertifyException.class, () ->
                credentialConfigurationService.deleteCredentialConfigurationById("12345678"));

        assertEquals("Configuration not found with the provided id: " + "12345678", exception.getMessage());
    }
}
