package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@WebMvcTest(value = CredentialConfigController.class)
public class CredentialConfigControllerTest {
    ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    MockMvc mockMvc;

    @MockBean
    ParsedAccessToken parsedAccessToken;

    @MockBean
    CredentialConfigurationService credentialConfigurationService;

    @Mock
    private CredentialConfigurationDTO credentialConfigurationDTO;

    @Before
    public void setup() {
        credentialConfigurationDTO = new CredentialConfigurationDTO();
        credentialConfigurationDTO.setVcTemplate("test_template");
        credentialConfigurationDTO.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTO.setCredentialType(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTO.setCredentialFormat("ldp_vc");
        credentialConfigurationDTO.setDidUrl("did:web:test.github.io:test-env:test-folder");
        credentialConfigurationDTO.setDisplay(List.of());
        credentialConfigurationDTO.setOrder(Arrays.asList("test1", "test2", "test3", "test4"));
        credentialConfigurationDTO.setScope("test_vc_ldp");
        credentialConfigurationDTO.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        credentialConfigurationDTO.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        Map<String, Object> jwtValues = Map.of("proof_signing_alg_values_supported", Arrays.asList("RS256", "ES256"));
        credentialConfigurationDTO.setProofTypesSupported(Map.of("jwt", jwtValues));
        Map<String, String> pluginConfigMap = new HashMap<>();
        pluginConfigMap.put("mosip.certify.mock.data-provider.test-one", "valueOne");
        pluginConfigMap.put("mosip.certify.mock.data-provider.test-two", "valueTwo");
        pluginConfigMap.put("mosip.certify.mock.data-provider.test-three", "valueThree");
        credentialConfigurationDTO.setPluginConfigurations(List.of(pluginConfigMap));
        credentialConfigurationDTO.setCredentialSubject(Map.of("name", "Full Name"));
    }

    @Test
    public void addNewCredentialConfiguration_Success() throws Exception {
        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId("farmer-credential-config-001");
        credentialConfigResponse.setStatus("active");
        Mockito.when(credentialConfigurationService.addCredentialConfiguration(credentialConfigurationDTO)).thenReturn(credentialConfigResponse);

        mockMvc.perform(post("/credentials/configurations")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationDTO))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.status").exists());
    }

    @Test
    public void getCredentialConfigurationById_Success() throws Exception {

        Mockito.when(credentialConfigurationService.getCredentialConfigurationById(Mockito.anyString())).thenReturn(credentialConfigurationDTO);

        mockMvc.perform(get("/credentials/configurations/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vcTemplate").exists())
                .andExpect(jsonPath("$.context").exists())
                .andExpect(jsonPath("$.credentialType").exists())
                .andExpect(jsonPath("$.didUrl").exists())
                .andExpect(jsonPath("$.scope").exists())
                .andExpect(jsonPath("$.cryptographic_binding_methods_supported").exists())
                .andExpect(jsonPath("$.credential_signing_alg_values_supported").exists())
                .andExpect(jsonPath("$.proof_types_supported").exists());
    }

    @Test
    public void updateExistingCredentialConfiguration_Success() throws Exception {
        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId("farmer-credential-config-001");
        credentialConfigResponse.setStatus("active");
        Mockito.when(credentialConfigurationService.updateCredentialConfiguration(Mockito.anyString(), eq(credentialConfigurationDTO))).thenReturn(credentialConfigResponse);

        mockMvc.perform(put("/credentials/configurations/1")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationDTO))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.status").exists());
    }

    @Test
    public void deleteExistingCredentialConfiguration_Success() throws Exception {
        String response = "Configuration deleted with id: 1";
        Mockito.when(credentialConfigurationService.deleteCredentialConfigurationById(Mockito.anyString())).thenReturn(response);

        mockMvc.perform(delete("/credentials/configurations/1"))
                .andExpect(status().isOk())
                .andExpect(content().string(response));
    }

        @Test
    public void getIssuerMetadata_noQueryParams_thenPass() throws Exception {
        CredentialIssuerMetadataVD13DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD13DTO();
        credentialIssuerMetadata.setCredentialIssuer("https://localhost:9090");
        credentialIssuerMetadata.setAuthorizationServers(List.of("https://example.com/auth"));
        credentialIssuerMetadata.setCredentialEndpoint("https://localhost:9090/v1/certify/issuance/credential");
        Map<String, String> display = new HashMap<>();
        display.put("name", "Test Credential Issuer");
        display.put("locale", "en");
        credentialIssuerMetadata.setDisplay(List.of(display));

        CredentialConfigurationSupportedDTO credentialConfigurationSupported = new CredentialConfigurationSupportedDTO();
        credentialConfigurationSupported.setFormat("ldp_vc");
        credentialConfigurationSupported.setScope("test_vc_ldp");
        credentialConfigurationSupported.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        credentialConfigurationSupported.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        Map<String, Object> jwtValues = Map.of("proof_signing_alg_values_supported", Arrays.asList("RS256", "ES256"));
        credentialConfigurationSupported.setProofTypesSupported(jwtValues);
        credentialConfigurationSupported.setDisplay(List.of());
        credentialConfigurationSupported.setOrder(Arrays.asList("test1", "test2", "test3", "test4"));
        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(Map.of("TestCredential_ldp", credentialConfigurationSupported));

        Mockito.when(credentialConfigurationService.fetchCredentialIssuerMetadata(Mockito.anyString())).thenReturn(credentialIssuerMetadata);

        mockMvc.perform(get("/credentials/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_issuer").exists())
                .andExpect(jsonPath("$.credential_configurations_supported").exists())
                .andExpect(header().string("Content-Type", "application/json"));

        Mockito.verify(credentialConfigurationService).fetchCredentialIssuerMetadata("latest");
    }
}
