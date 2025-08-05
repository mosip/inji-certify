package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.CredentialConfigResponse;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialSubjectParametersDTO;
import io.mosip.certify.core.dto.ParsedAccessToken;
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
        credentialConfigurationDTO.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        credentialConfigurationDTO.setCredentialTypes(Arrays.asList("VerifiableCredential", "TestVerifiableCredential"));
        credentialConfigurationDTO.setCredentialFormat("ldp_vc");
        credentialConfigurationDTO.setDidUrl("did:web:test.github.io:test-env:test-folder");
        credentialConfigurationDTO.setMetaDataDisplay(List.of());
        credentialConfigurationDTO.setDisplayOrder(Arrays.asList("test1", "test2", "test3", "test4"));
        credentialConfigurationDTO.setScope("test_vc_ldp");
        credentialConfigurationDTO.setSignatureCryptoSuite("Ed25519Signature2020");
        Map<String, Object> jwtValues = Map.of("proof_signing_alg_values_supported", Arrays.asList("RS256", "ES256"));
        Map<String, String> pluginConfigMap = new HashMap<>();
        pluginConfigMap.put("mosip.certify.mock.data-provider.test-one", "valueOne");
        pluginConfigMap.put("mosip.certify.mock.data-provider.test-two", "valueTwo");
        pluginConfigMap.put("mosip.certify.mock.data-provider.test-three", "valueThree");
        credentialConfigurationDTO.setPluginConfigurations(List.of(pluginConfigMap));
        credentialConfigurationDTO.setCredentialSubjectDefinition(Map.of(
                "name", new CredentialSubjectParametersDTO(List.of(new CredentialSubjectParametersDTO.Display("Full Name", "en")))
        ));
    }

    @Test
    public void addNewCredentialConfiguration_Success() throws Exception {
        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId("farmer-credential-config-001");
        credentialConfigResponse.setStatus("active");
        Mockito.when(credentialConfigurationService.addCredentialConfiguration(credentialConfigurationDTO)).thenReturn(credentialConfigResponse);

        mockMvc.perform(post("/credential-configurations")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationDTO))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.status").exists());
    }

    @Test
    public void getCredentialConfigurationById_Success() throws Exception {

        Mockito.when(credentialConfigurationService.getCredentialConfigurationById(Mockito.anyString())).thenReturn(credentialConfigurationDTO);

        mockMvc.perform(get("/credential-configurations/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vcTemplate").exists())
                .andExpect(jsonPath("$.contextURLs").exists())
                .andExpect(jsonPath("$.credentialTypes").exists())
                .andExpect(jsonPath("$.didUrl").exists())
                .andExpect(jsonPath("$.scope").exists());
    }

    @Test
    public void updateExistingCredentialConfiguration_Success() throws Exception {
        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId("farmer-credential-config-001");
        credentialConfigResponse.setStatus("active");
        Mockito.when(credentialConfigurationService.updateCredentialConfiguration(Mockito.anyString(), eq(credentialConfigurationDTO))).thenReturn(credentialConfigResponse);

        mockMvc.perform(put("/credential-configurations/1")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationDTO))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.status").exists());
    }

    @Test
    public void deleteExistingCredentialConfiguration_Success() throws Exception {
        Mockito.when(credentialConfigurationService.deleteCredentialConfigurationById(Mockito.anyString())).thenReturn("1");

        mockMvc.perform(delete("/credential-configurations/1"))
                .andExpect(status().isOk())
                .andExpect(content().string("Deleted configuration with id: 1"));
    }
}
