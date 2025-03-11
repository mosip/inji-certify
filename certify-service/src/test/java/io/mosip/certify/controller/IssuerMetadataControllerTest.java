package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import io.mosip.certify.core.dto.CredentialDisplay;
import io.mosip.certify.core.dto.CredentialIssuerMetadata;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.spi.VCIssuanceService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@WebMvcTest(value = IssuerMetadataController.class)
public class IssuerMetadataControllerTest {
    @Autowired
    MockMvc mockMvc;

    @MockBean
    ParsedAccessToken parsedAccessToken;

    @MockBean
    VCIssuanceService vcIssuanceService;

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

        mockMvc.perform(get("/issuer-metadata/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_issuer").exists())
                .andExpect(jsonPath("$.credential_configurations_supported").exists())
                .andExpect(header().string("Content-Type", "application/json"));

        Mockito.verify(vcIssuanceService).fetchCredentialIssuerMetadata("latest");
    }
}
