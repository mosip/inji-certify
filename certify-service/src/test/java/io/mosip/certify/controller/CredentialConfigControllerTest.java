package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CredentialConfigValidationException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
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

    // AccessTokenValidationFilter is a @Component, so the web slice builds it
    // and every collaborator it autowires has to exist here too.
    @MockBean
    io.mosip.certify.dpop.DpopProofValidator dpopProofValidator;

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
        credentialConfigurationDTO.setClaims(Map.of(
                "name", new ClaimsDTO(List.of(new ClaimsDTO.Display("Full Name", "en")))
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

    /**
     * AC-2 over the wire: the three optional attributes bind from the request JSON onto the DTO the
     * service receives, rather than being dropped between Jackson and the controller.
     */
    @Test
    public void addCredentialConfiguration_BindsTheThreeMetadataAttributes() throws Exception {
        credentialConfigurationDTO.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        credentialConfigurationDTO.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        credentialConfigurationDTO.setProofTypesSupported(
                Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))));

        CredentialConfigResponse response = new CredentialConfigResponse();
        response.setId("farmer-credential-config-001");
        response.setStatus("active");
        ArgumentCaptor<CredentialConfigurationDTO> captor = ArgumentCaptor.forClass(CredentialConfigurationDTO.class);
        Mockito.when(credentialConfigurationService.addCredentialConfiguration(captor.capture())).thenReturn(response);

        mockMvc.perform(post("/credential-configurations")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationDTO))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isCreated());

        CredentialConfigurationDTO received = captor.getValue();
        Assert.assertEquals(List.of("did:jwk"), received.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), received.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))),
                received.getProofTypesSupported());
    }

    /**
     * AC-6, AC-7 over the wire: the Get response carries all three attributes.
     */
    @Test
    public void getCredentialConfigurationById_ReturnsTheThreeMetadataAttributes() throws Exception {
        credentialConfigurationDTO.setCryptographicBindingMethodsSupported(List.of("did:jwk", "did:key"));
        credentialConfigurationDTO.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        credentialConfigurationDTO.setProofTypesSupported(
                Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("RS256", "ES256"))));
        Mockito.when(credentialConfigurationService.getCredentialConfigurationById(Mockito.anyString()))
                .thenReturn(credentialConfigurationDTO);

        mockMvc.perform(get("/credential-configurations/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cryptographicBindingMethodsSupported").value(Matchers.contains("did:jwk", "did:key")))
                .andExpect(jsonPath("$.credentialSigningAlgValuesSupported").value(Matchers.contains("EdDSA")))
                .andExpect(jsonPath("$.proofTypesSupported.jwt.proof_signing_alg_values_supported")
                        .value(Matchers.contains("RS256", "ES256")));
    }

    /**
     * BR-CM-3 and the aggregation rule over the wire: every failure across the three attributes reaches
     * the caller in one errors array, so the whole payload can be corrected in a single pass.
     */
    @Test
    public void addCredentialConfiguration_ReportsEveryValidationFailureTogether() throws Exception {
        Mockito.when(credentialConfigurationService.addCredentialConfiguration(Mockito.any()))
                .thenThrow(new CredentialConfigValidationException(List.of(
                        new io.mosip.certify.core.dto.Error(ErrorConstants.UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD,
                                "The cryptographic binding method cose_key is not supported for the credential format ldp_vc."),
                        new io.mosip.certify.core.dto.Error(ErrorConstants.UNSUPPORTED_PROOF_SIGNING_ALG,
                                "The proof signing algorithm HS256 is not supported for the proof type jwt."))));

        mockMvc.perform(post("/credential-configurations")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationDTO))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors", Matchers.hasSize(2)))
                .andExpect(jsonPath("$.errors[0].errorCode")
                        .value(ErrorConstants.UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD))
                .andExpect(jsonPath("$.errors[1].errorCode")
                        .value(ErrorConstants.UNSUPPORTED_PROOF_SIGNING_ALG));
    }
}
