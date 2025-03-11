package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.VCIssuanceService;
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

    @MockBean
    VCIssuanceService vcIssuanceService;

    @Mock
    private CredentialConfigurationRequest credentialConfigurationRequest;

    @Before
    public void setup() {
        credentialConfigurationRequest = new CredentialConfigurationRequest();
        credentialConfigurationRequest.setVcTemplate("test_template");
        credentialConfigurationRequest.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationRequest.setCredentialType(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationRequest.setCredentialFormat("ldp_vc");
        credentialConfigurationRequest.setDidUrl("did:web:test.github.io:test-env:test-folder");
        CredentialDisplay credentialDisplay = new CredentialDisplay();
        credentialDisplay.setName("Test Verifiable Credential");
        credentialDisplay.setLocale("en");
        credentialDisplay.setBackgroundColor("#FDFAF9");
        credentialDisplay.setTextColor("#7C4616");
        credentialDisplay.setLogo(Map.of("url", "https://www.example.com", "alt_text", "test"));
        credentialConfigurationRequest.setDisplay(credentialDisplay);
        credentialConfigurationRequest.setOrder(Arrays.asList("test1", "test2", "test3", "test4"));
        credentialConfigurationRequest.setScope("test_vc_ldp");
        credentialConfigurationRequest.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        credentialConfigurationRequest.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        Map<String, Object> jwtValues = Map.of("proof_signing_alg_values_supported", Arrays.asList("RS256", "ES256"));
        credentialConfigurationRequest.setProofTypesSupported(Map.of("jwt", jwtValues));
        Map<String, String> pluginConfigMap = new HashMap<>();
        pluginConfigMap.put("mosip.certify.mock.data-provider.test-one", "valueOne");
        pluginConfigMap.put("mosip.certify.mock.data-provider.test-two", "valueTwo");
        pluginConfigMap.put("mosip.certify.mock.data-provider.test-three", "valueThree");
        credentialConfigurationRequest.setPluginConfigurations(List.of(pluginConfigMap));
    }

    @Test
    public void addNewCredentialConfiguration_Success() throws Exception {


        Map<String, String> configurationResponse = new HashMap<>();
        configurationResponse.put("id", "farmer-credential-config-001");
        configurationResponse.put("status", "active");
        Mockito.when(credentialConfigurationService.addCredentialConfiguration(credentialConfigurationRequest)).thenReturn(configurationResponse);

        mockMvc.perform(post("/credentials/configurations")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.status").exists());
    }

    @Test
    public void getCredentialConfigurationById_Success() throws Exception {

        Mockito.when(credentialConfigurationService.getCredentialConfigurationById(Mockito.anyString())).thenReturn(credentialConfigurationRequest);

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
        Map<String, String> configurationResponse = new HashMap<>();
        configurationResponse.put("id", "farmer-credential-config-001");
        configurationResponse.put("status", "active");
        Mockito.when(credentialConfigurationService.updateCredentialConfiguration(Mockito.anyString(), eq(credentialConfigurationRequest))).thenReturn(configurationResponse);

        mockMvc.perform(put("/credentials/configurations/1")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.status").exists());
    }
}
