package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.services.VCICacheService;
import org.junit.Test;
import org.junit.runner.RunWith;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

@RunWith(SpringRunner.class)
@WebMvcTest(value = CredentialConfigController.class)
public class CredentialConfigControllerTest {

    ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    MockMvc mockMvc;

    @MockBean
    ParsedAccessToken parsedAccessToken;

    @MockBean
    VCIssuanceService vcIssuanceService;

    @MockBean
    VCICacheService vciCacheService;

    @Test
    public void addNewCredentialConfiguration_Success() throws Exception {
        CredentialConfigurationRequest credentialConfigurationRequest = new CredentialConfigurationRequest();
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

        Map<String, String> configurationResponse = new HashMap<>();
        configurationResponse.put("id", "farmer-credential-config-001");
        configurationResponse.put("status", "active");
        Mockito.when(vcIssuanceService.addCredentialConfiguration(credentialConfigurationRequest)).thenReturn(configurationResponse);

        mockMvc.perform(post("/config/credentials/configurations")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.status").exists());
    }

    @Test
    public void getIssuerMetadata_noQueryParams_thenPass() throws Exception {
        CredentialIssuerMetadata credentialIssuerMetadata = new CredentialIssuerMetadata();
        credentialIssuerMetadata.setCredentialIssuer("https://localhost:9090");
        credentialIssuerMetadata.setAuthorizationServers(List.of("https://example.com/auth"));
        credentialIssuerMetadata.setCredentialEndpoint("https://localhost:9090/v1/certify/issuance/credential");
        Map<String, String> display = new HashMap<>();
        display.put("name", "Test Credential Issuer");
        display.put("locale", "en");
        credentialIssuerMetadata.setDisplay(display);

        CredentialConfigurationSupported credentialConfigurationSupported = new CredentialConfigurationSupported();
        credentialConfigurationSupported.setFormat("ldp_vc");
        credentialConfigurationSupported.setScope("test_vc_ldp");
        credentialConfigurationSupported.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        credentialConfigurationSupported.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        Map<String, Object> jwtValues = Map.of("proof_signing_alg_values_supported", Arrays.asList("RS256", "ES256"));
        credentialConfigurationSupported.setProofTypesSupported(jwtValues);
        CredentialDisplay credentialDisplay = new CredentialDisplay();
        credentialDisplay.setName("Test Verifiable Credential");
        credentialDisplay.setLocale("en");
        credentialDisplay.setBackgroundColor("#FDFAF9");
        credentialDisplay.setTextColor("#7C4616");
        credentialDisplay.setLogo(Map.of("url", "https://www.example.com", "alt_text", "test"));
        credentialConfigurationSupported.setDisplay(credentialDisplay);
        credentialConfigurationSupported.setOrder(Arrays.asList("test1", "test2", "test3", "test4"));
        credentialIssuerMetadata.setCredentialConfigurationSupported(Map.of("TestCredential_ldp", credentialConfigurationSupported));

        Mockito.when(vcIssuanceService.fetchCredentialIssuerMetadata(Mockito.anyString())).thenReturn(credentialIssuerMetadata);

        mockMvc.perform(get("/config/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_issuer").exists())
                .andExpect(jsonPath("$.credential_issuer").exists())
                .andExpect(jsonPath("$.credential_configurations_supported").exists())
                .andExpect(header().string("Content-Type", "application/json"));

        Mockito.verify(vcIssuanceService).fetchCredentialIssuerMetadata("latest");
    }
}
