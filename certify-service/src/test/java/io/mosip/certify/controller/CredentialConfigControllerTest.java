package io.mosip.certify.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CredentialConfigValidationException;
import io.mosip.certify.config.AppConfig;
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
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
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
@Import(CredentialConfigControllerTest.ApplicationObjectMapper.class)
public class CredentialConfigControllerTest {

    /**
     * Binds requests with the application's own ObjectMapper, as the running service does, rather than
     * the web slice's default one, which tolerates unrecognised fields that the service rejects.
     */
    @TestConfiguration
    static class ApplicationObjectMapper {
        @Bean
        ObjectMapper objectMapper() {
            return new AppConfig().objectMapper();
        }
    }
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
        Map<String, Object> jwtValues = Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, Arrays.asList("RS256", "ES256"));
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
     * The two attributes the request carries bind from the request JSON onto the DTO the service
     * receives, rather than being dropped between Jackson and the controller.
     */
    @Test
    public void should_bindMetadataAttributes_when_addRequestCarriesThem() throws Exception {
        credentialConfigurationDTO.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        credentialConfigurationDTO.setProofTypesSupported(
                Map.of("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("ES256"))));

        CredentialConfigResponse response = new CredentialConfigResponse();
        response.setId("farmer-credential-config-001");
        response.setStatus("active");
        Mockito.when(credentialConfigurationService.addCredentialConfiguration(Mockito.any(CredentialConfigurationDTO.class)))
                .thenReturn(response);

        mockMvc.perform(post("/credential-configurations")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationDTO))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isCreated());

        ArgumentCaptor<CredentialConfigurationDTO> captor = ArgumentCaptor.forClass(CredentialConfigurationDTO.class);
        Mockito.verify(credentialConfigurationService).addCredentialConfiguration(captor.capture());
        CredentialConfigurationDTO received = captor.getValue();
        Assert.assertEquals(List.of("did:jwk"), received.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("ES256"))),
                received.getProofTypesSupported());
    }

    /**
     * credentialSigningAlgValuesSupported is no longer part of the request. A client that still sends it
     * is rejected as an unrecognised field before the service is reached, so nothing is stored and the
     * client has to change its request body.
     */
    @Test
    public void should_rejectRequest_when_itSendsCredentialSigningAlgValuesSupported() throws Exception {
        credentialConfigurationDTO.setSignatureAlgo("EdDSA");
        Map<String, Object> withSigningAlgs = new HashMap<>(objectMapper.convertValue(credentialConfigurationDTO,
                new TypeReference<Map<String, Object>>() {}));
        withSigningAlgs.put("credentialSigningAlgValuesSupported", List.of("ES256K"));

        mockMvc.perform(post("/credential-configurations")
                        .content(objectMapper.writeValueAsBytes(withSigningAlgs))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode").value(ErrorConstants.INVALID_REQUEST))
                .andExpect(jsonPath("$.errors[0].errorMessage")
                        .value("Unrecognized field 'credentialSigningAlgValuesSupported' in request"));

        Mockito.verify(credentialConfigurationService, Mockito.never())
                .addCredentialConfiguration(Mockito.any(CredentialConfigurationDTO.class));
    }

    /**
     * A request that leaves the two attributes out and one that sends them as null reach the service
     * identically, so the service rejects a missing attribute and a null one the same way.
     */
    @Test
    public void should_bindAttributesAsNull_when_addRequestOmitsOrNullsThem() throws Exception {
        Mockito.when(credentialConfigurationService.addCredentialConfiguration(Mockito.any(CredentialConfigurationDTO.class)))
                .thenReturn(new CredentialConfigResponse());
        Map<String, Object> withNulls = new HashMap<>(objectMapper.convertValue(credentialConfigurationDTO,
                new TypeReference<Map<String, Object>>() {}));
        withNulls.put("cryptographicBindingMethodsSupported", null);
        withNulls.put("proofTypesSupported", null);

        mockMvc.perform(post("/credential-configurations")
                        .content(objectMapper.writeValueAsBytes(credentialConfigurationDTO))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isCreated());
        mockMvc.perform(post("/credential-configurations")
                        .content(objectMapper.writeValueAsBytes(withNulls))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isCreated());

        ArgumentCaptor<CredentialConfigurationDTO> captor = ArgumentCaptor.forClass(CredentialConfigurationDTO.class);
        Mockito.verify(credentialConfigurationService, Mockito.times(2)).addCredentialConfiguration(captor.capture());
        for (CredentialConfigurationDTO received : captor.getAllValues()) {
            Assert.assertNull(received.getCryptographicBindingMethodsSupported());
            Assert.assertNull(received.getProofTypesSupported());
        }
    }

    /**
     * The Get response carries the two attributes and the signing algorithm, which is returned as
     * signatureAlgo rather than as a separate list.
     */
    @Test
    public void should_returnMetadataAttributesAndSignatureAlgo_when_configurationIsFetched() throws Exception {
        credentialConfigurationDTO.setCryptographicBindingMethodsSupported(List.of("did:jwk", "did:key"));
        credentialConfigurationDTO.setSignatureAlgo("EdDSA");
        credentialConfigurationDTO.setProofTypesSupported(
                Map.of("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, List.of("RS256", "ES256"))));
        Mockito.when(credentialConfigurationService.getCredentialConfigurationById(Mockito.anyString()))
                .thenReturn(credentialConfigurationDTO);

        mockMvc.perform(get("/credential-configurations/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cryptographicBindingMethodsSupported").value(Matchers.contains("did:jwk", "did:key")))
                .andExpect(jsonPath("$.signatureAlgo").value("EdDSA"))
                .andExpect(jsonPath("$.credentialSigningAlgValuesSupported").doesNotExist())
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
