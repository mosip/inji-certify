package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.OAuthASMetadataDTO;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.services.OAuthASMetadataService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(WellKnownController.class)
class WellKnownControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CredentialConfigurationService credentialConfigurationService;

    @MockBean
    private VCIssuanceService vcIssuanceService;

    @MockBean
    private OAuthASMetadataService oAuthASMetadataService;

    @MockBean
    private ParsedAccessToken parsedAccessToken;

    @InjectMocks
    private WellKnownController wellKnownController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getCredentialIssuerMetadata_noVersionParam_defaultsToLatest() throws Exception {
        CredentialIssuerMetadataDTO mockMetadata = mock(CredentialIssuerMetadataDTO.class);
        when(credentialConfigurationService.fetchCredentialIssuerMetadata("latest")).thenReturn(mockMetadata);
        mockMvc.perform(get("/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk());
        verify(credentialConfigurationService, times(1)).fetchCredentialIssuerMetadata("latest");
    }

    @Test
    void getCredentialIssuerMetadata_emptyVersion_defaultsToLatest() throws Exception {
        CredentialIssuerMetadataDTO mockMetadata = mock(CredentialIssuerMetadataDTO.class);
        when(credentialConfigurationService.fetchCredentialIssuerMetadata("latest")).thenReturn(mockMetadata);
        mockMvc.perform(get("/.well-known/openid-credential-issuer?version="))
                .andExpect(status().isOk());
        verify(credentialConfigurationService, times(1)).fetchCredentialIssuerMetadata("latest");
    }

    @Test
    void getCredentialIssuerMetadata_unsupportedVersion_returnsError() throws Exception {
        when(credentialConfigurationService.fetchCredentialIssuerMetadata("unsupported")).thenThrow( new CertifyException("UNSUPPORTED_VERSION", "Unsupported version"));
        mockMvc.perform(get("/.well-known/openid-credential-issuer?version=unsupported"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(jsonPath("$.errors[0].errorCode").value("UNSUPPORTED_VERSION"));
    }

    @Test
    void getDIDDocument_success() throws Exception {
        Map<String, Object> mockDidDoc = Collections.singletonMap("id", "did:example:123");
        when(vcIssuanceService.getDIDDocument()).thenReturn(mockDidDoc);
        mockMvc.perform(get("/.well-known/did.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("did:example:123"));
    }

    @Test
    void getDIDDocument_notFound_returnsEmpty() throws Exception {
        when(vcIssuanceService.getDIDDocument()).thenReturn(null);
        mockMvc.perform(get("/.well-known/did.json"))
                .andExpect(status().isOk())
                .andExpect(content().string(""));
    }

    @Test
    void getDIDDocument_serviceThrowsException_returnsError() throws Exception {
        when(vcIssuanceService.getDIDDocument()).thenThrow(new InvalidRequestException("unsupported_in_current_plugin_mode"));
        mockMvc.perform(get("/.well-known/did.json"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(jsonPath("$.errors[0].errorCode").value("unsupported_in_current_plugin_mode"));
    }

    @Test
    void getOAuthASMetadata_success() throws Exception {
        // Arrange
        OAuthASMetadataDTO mockMetadata = new OAuthASMetadataDTO();
        mockMetadata.setIssuer("http://localhost:8090/v1/certify");
        mockMetadata.setTokenEndpoint("http://localhost:8090/v1/certify/oauth/token");
        mockMetadata.setJwksUri("http://localhost:8090/v1/certify/.well-known/jwks.json");
        mockMetadata.setGrantTypesSupported(Arrays.asList("authorization_code", "pre-authorized_code"));
        mockMetadata.setResponseTypesSupported(Arrays.asList("code"));
        mockMetadata.setTokenEndpointAuthMethodsSupported(Arrays.asList("client_secret_basic", "client_secret_post"));
        mockMetadata.setIntrospectionEndpoint("http://localhost:8090/v1/certify/oauth/introspect");
        mockMetadata.setAuthorizationChallengeEndpoint("http://localhost:8090/v1/certify/oauth/challenge");

        when(oAuthASMetadataService.getOAuthASMetadata()).thenReturn(mockMetadata);

        // Act & Assert
        mockMvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.issuer").value("http://localhost:8090/v1/certify"))
                .andExpect(jsonPath("$.token_endpoint").value("http://localhost:8090/v1/certify/oauth/token"))
                .andExpect(jsonPath("$.jwks_uri").value("http://localhost:8090/v1/certify/.well-known/jwks.json"))
                .andExpect(jsonPath("$.grant_types_supported[0]").value("authorization_code"))
                .andExpect(jsonPath("$.grant_types_supported[1]").value("pre-authorized_code"))
                .andExpect(jsonPath("$.response_types_supported[0]").value("code"))
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported[0]").value("client_secret_basic"))
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported[1]").value("client_secret_post"))
                .andExpect(jsonPath("$.introspection_endpoint").value("http://localhost:8090/v1/certify/oauth/introspect"))
                .andExpect(jsonPath("$.authorization_challenge_endpoint").value("http://localhost:8090/v1/certify/oauth/challenge"));

        verify(oAuthASMetadataService, times(1)).getOAuthASMetadata();
    }
}
