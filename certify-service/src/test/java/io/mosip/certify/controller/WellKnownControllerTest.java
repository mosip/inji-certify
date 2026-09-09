package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.core.spi.VCIssuanceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;
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
    private ParsedAccessToken parsedAccessToken;

    // AccessTokenValidationFilter is a @Component, so the web slice builds it
    // and every collaborator it autowires has to exist here too.
    @MockBean
    private io.mosip.certify.dpop.DpopProofValidator dpopProofValidator;

    @MockBean
    private JwksService jwksService;

    @InjectMocks
    private WellKnownController wellKnownController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getCredentialIssuerMetadata() throws Exception {
        CredentialIssuerMetadataDTO mockMetadata = mock(CredentialIssuerMetadataDTO.class);
        when(credentialConfigurationService.fetchCredentialIssuerMetadata()).thenReturn(mockMetadata);
        mockMvc.perform(get("/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk());
        verify(credentialConfigurationService, times(1)).fetchCredentialIssuerMetadata();
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
    void getJwks_success_returnsJwkSet() throws Exception {
        Map<String, Object> mockJwks = Map.of(
                "keys", Collections.singletonList(
                        Map.of(
                                "kty", "RSA",
                                "kid", "test-key-id",
                                "use", "sig",
                                "n", "test-modulus",
                                "e", "AQAB"
                        )
                )
        );
        when(jwksService.getJwks()).thenReturn(mockJwks);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value("test-key-id"));

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_emptyKeysList_returnsOkWithEmptyKeys() throws Exception {
        Map<String, Object> emptyJwks = Map.of("keys", Collections.emptyList());
        when(jwksService.getJwks()).thenReturn(emptyJwks);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_nullResponse_returnsServiceUnavailable() throws Exception {
        when(jwksService.getJwks()).thenReturn(null);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_missingKeysField_returnsServiceUnavailable() throws Exception {
        Map<String, Object> invalidResponse = Collections.singletonMap("invalid", "response");
        when(jwksService.getJwks()).thenReturn(invalidResponse);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_serviceThrowsException_returnsServiceUnavailable() throws Exception {
        when(jwksService.getJwks()).thenThrow(new RuntimeException("Keymanager service unavailable"));

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_nullKeysList_returnsOkWithEmptyKeys() throws Exception {
        Map<String, Object> nullKeysResponse = Collections.singletonMap("keys", null);
        when(jwksService.getJwks()).thenReturn(nullKeysResponse);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").doesNotExist());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_multipleKeys_returnsAllKeys() throws Exception {
        Map<String, Object> mockJwks = Map.of(
                "keys", List.of(
                        Map.of("kty", "RSA", "kid", "key1", "use", "sig"),
                        Map.of("kty", "EC", "kid", "key2", "use", "sig")
                )
        );
        when(jwksService.getJwks()).thenReturn(mockJwks);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys.length()").value(2))
                .andExpect(jsonPath("$.keys[0].kid").value("key1"))
                .andExpect(jsonPath("$.keys[1].kid").value("key2"));

        verify(jwksService, times(1)).getJwks();
    }
}