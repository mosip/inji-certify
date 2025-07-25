package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.exception.InvalidNonceException;
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

@RunWith(SpringRunner.class)
@WebMvcTest(value = VCIssuanceController.class)
public class VCIssuanceControllerTest {

    ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    MockMvc mockMvc;

    @MockBean
    AuditPlugin auditWrapper;


    @MockBean
    ParsedAccessToken parsedAccessToken;

    @MockBean
    VCIssuanceService vcIssuanceService;

    @MockBean
    VCICacheService vciCacheService;

    @MockBean
    CredentialConfigurationService credentialConfigurationService;

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

        mockMvc.perform(get("/issuance/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_issuer").exists())
                .andExpect(jsonPath("$.credential_issuer").exists())
                .andExpect(jsonPath("$.credential_configurations_supported").exists())
                .andExpect(header().string("Content-Type", "application/json"));

        Mockito.verify(credentialConfigurationService).fetchCredentialIssuerMetadata("latest");
    }

    @Test
    public void getIssuerMetadata_withValidQueryParam_thenPass() throws Exception {
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


        Mockito.when(credentialConfigurationService.fetchCredentialIssuerMetadata("vd13")).thenReturn(credentialIssuerMetadata);

        mockMvc.perform(get("/issuance/.well-known/openid-credential-issuer?version=vd13"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_issuer").exists())
                .andExpect(jsonPath("$.credential_endpoint").exists())
                .andExpect(jsonPath("$.credential_configurations_supported").exists())
                .andExpect(header().string("Content-Type", "application/json"));

        Mockito.verify(credentialConfigurationService).fetchCredentialIssuerMetadata("vd13");
    }

    @Test
    public void getIssuerMetadata_withInvalidQueryParam_thenFail() throws Exception {
        Exception e = new InvalidRequestException(ErrorConstants.UNSUPPORTED_OPENID_VERSION);
        Mockito.when(credentialConfigurationService.fetchCredentialIssuerMetadata("v123")).thenThrow(e);
        mockMvc.perform(get("/issuance/.well-known/openid-credential-issuer?version=v123"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    public void getVerifiableCredential_withValidDetails_thenPass() throws Exception {
        CredentialDefinition credentialDefinition = new CredentialDefinition();
        credentialDefinition.setType(Arrays.asList("VerifiableCredential", "SampleVerifiableCredential_ldp"));
        credentialDefinition.setContext(Arrays.asList("https://www.w3.org/2018/credentials/v1"));
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setProof_type("jwt");
        credentialProof.setJwt("dummy_jwt_proof");
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setFormat("ldp_vc");
        credentialRequest.setProof(credentialProof);
        credentialRequest.setCredential_definition(credentialDefinition);

        CredentialResponse credentialResponse = new CredentialResponse<JsonLDObject>();
        credentialResponse.setCredential(new JsonLDObject());
        Mockito.when(vcIssuanceService.getCredential(credentialRequest)).thenReturn(credentialResponse);

        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential").exists());
    }

    @Test
    public void getVerifiableCredential_withInvalidFormat_thenFail() throws Exception {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setFormat(null);
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setProof_type("jwt");
        credentialRequest.setProof(credentialProof);
        CredentialDefinition credentialDefinition = new CredentialDefinition();
        credentialDefinition.setType(Arrays.asList("VerifiableCredential", "SampleVerifiableCredential_ldp"));
        credentialRequest.setCredential_definition(credentialDefinition);

        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(ErrorConstants.INVALID_VC_FORMAT));

        credentialRequest.setFormat("  ");
        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(ErrorConstants.INVALID_VC_FORMAT));
    }

    @Test
    public void getVerifiableCredential_withInvalidProof_thenFail() throws Exception {
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setFormat("jwt_vc_json");
        CredentialDefinition credentialDefinition = new CredentialDefinition();
        credentialDefinition.setType(Arrays.asList("VerifiableCredential", "SampleVerifiableCredential_ldp"));
        credentialRequest.setCredential_definition(credentialDefinition);

        credentialRequest.setProof(null);
        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(ErrorConstants.INVALID_PROOF));

        CredentialProof credentialProof = new CredentialProof();
        credentialRequest.setProof(credentialProof);
        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(ErrorConstants.UNSUPPORTED_PROOF_TYPE));


        credentialProof.setProof_type("  ");
        credentialRequest.setProof(credentialProof);
        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(ErrorConstants.UNSUPPORTED_PROOF_TYPE));
    }

    @Test
    public void getVerifiableCredential_withInvalidNonceException_thenFail() throws Exception {
        CredentialDefinition credentialDefinition = new CredentialDefinition();
        credentialDefinition.setType(Arrays.asList("VerifiableCredential", "SampleVerifiableCredential_ldp"));
        credentialDefinition.setContext(Arrays.asList("https://www.w3.org/2018/credentials/v1"));
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setProof_type("jwt");
        credentialProof.setJwt("dummy_jwt_proof");
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setFormat("ldp_vc");
        credentialRequest.setProof(credentialProof);
        credentialRequest.setCredential_definition(credentialDefinition);

        InvalidNonceException exception = new InvalidNonceException("test-new-nonce", 400);
        Mockito.when(vcIssuanceService.getCredential(credentialRequest)).thenThrow(exception);

        mockMvc.perform(post("/issuance/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(exception.getErrorCode()))
                .andExpect(jsonPath("$.c_nonce_expires_in").value(exception.getClientNonceExpireSeconds()))
                .andExpect(jsonPath("$.c_nonce").value(exception.getClientNonce()));
    }

    @Test
    public void getVerifiableCredential_vd11() throws Exception {
        CredentialDefinition credentialDefinition = new CredentialDefinition();
        credentialDefinition.setType(Arrays.asList("VerifiableCredential", "SampleVerifiableCredential_ldp"));
        credentialDefinition.setContext(Arrays.asList("https://www.w3.org/2018/credentials/v1"));
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setProof_type("jwt");
        credentialProof.setJwt("dummy_jwt_proof");
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setFormat("ldp_vc");
        credentialRequest.setProof(credentialProof);
        credentialRequest.setCredential_definition(credentialDefinition);

        CredentialResponse credentialResponse = new CredentialResponse<JsonLDObject>();
        credentialResponse.setFormat("ldp_vc");
        credentialResponse.setCredential(new JsonLDObject());
        Mockito.when(vcIssuanceService.getCredential(credentialRequest)).thenReturn(credentialResponse);

        mockMvc.perform(post("/issuance/vd11/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.format").exists())
                .andExpect(jsonPath("$.credential").exists());
    }

    @Test
    public void getVerifiableCredential_vd12() throws Exception {
        CredentialDefinition credentialDefinition = new CredentialDefinition();
        credentialDefinition.setType(Arrays.asList("VerifiableCredential", "SampleVerifiableCredential_ldp"));
        credentialDefinition.setContext(Arrays.asList("https://www.w3.org/2018/credentials/v1"));
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setProof_type("jwt");
        credentialProof.setJwt("dummy_jwt_proof");
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setFormat("ldp_vc");
        credentialRequest.setProof(credentialProof);
        credentialRequest.setCredential_definition(credentialDefinition);

        CredentialResponse credentialResponse = new CredentialResponse<JsonLDObject>();
        credentialResponse.setFormat("ldp_vc");
        credentialResponse.setCredential(new JsonLDObject());
        Mockito.when(vcIssuanceService.getCredential(credentialRequest)).thenReturn(credentialResponse);

        mockMvc.perform(post("/issuance/vd12/credential")
                        .content(objectMapper.writeValueAsBytes(credentialRequest))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.format").exists())
                .andExpect(jsonPath("$.credential").exists());
    }
}
