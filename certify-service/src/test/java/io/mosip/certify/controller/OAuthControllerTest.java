package io.mosip.certify.controller;

import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.constants.InteractionType;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.IarService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.filter.AccessTokenValidationFilter;
import io.mosip.certify.services.OAuthAuthorizationServerMetadataService;
import io.mosip.certify.services.PreAuthorizedCodeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for OAuthController
 * Tests the Interactive Authorization Request (IAR) endpoint functionality
 */
@WebMvcTest(value = OAuthController.class,
             excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, 
                                                  classes = {AccessTokenValidationFilter.class}))
class OAuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private OAuthAuthorizationServerMetadataService oAuthAuthorizationServerMetadataService;

    @MockBean
    private IarService iarService;

    @MockBean
    private MessageSource messageSource;

    @MockBean
    private PreAuthorizedCodeService preAuthorizedCodeService;

    @BeforeEach
    void setUp() {
        // Setup default message source behavior
        when(messageSource.getMessage(eq("invalid_request"), any(), anyString(), any(Locale.class)))
                .thenReturn("invalid_request");
        when(messageSource.getMessage(eq("interaction_required"), any(), anyString(), any(Locale.class)))
                .thenReturn("Interaction required");
        when(messageSource.getMessage(anyString(), any(), anyString(), any(Locale.class)))
                .thenAnswer(invocation -> invocation.getArgument(2));
    }

    @Test
    void getOAuthAuthorizationServerMetadata_success() throws Exception {
        // Arrange
        OAuthAuthorizationServerMetadataDTO mockMetadata = new OAuthAuthorizationServerMetadataDTO();
        mockMetadata.setIssuer("http://localhost:8090");
        mockMetadata.setTokenEndpoint("http://localhost:8090/v1/certify/oauth/token");
        mockMetadata.setJwksUri("http://localhost:8090/v1/certify/oauth/.well-known/jwks.json");
        mockMetadata.setGrantTypesSupported(Arrays.asList("authorization_code"));
        mockMetadata.setResponseTypesSupported(Arrays.asList("code"));
        mockMetadata.setCodeChallengeMethodsSupported(Arrays.asList("S256"));
        mockMetadata.setInteractiveAuthorizationEndpoint("http://localhost:8090/v1/certify/oauth/iae");
        mockMetadata.setRequireInteractiveAuthorizationRequest(true);

        when(oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata()).thenReturn(mockMetadata);

        // Act & Assert
        mockMvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.issuer").value("http://localhost:8090"))
                .andExpect(jsonPath("$.token_endpoint").value("http://localhost:8090/v1/certify/oauth/token"))
                .andExpect(jsonPath("$.grant_types_supported[0]").value("authorization_code"))
                .andExpect(jsonPath("$.response_types_supported[0]").value("code"))
                .andExpect(jsonPath("$.code_challenge_methods_supported[0]").value("S256"))
                .andExpect(jsonPath("$.interactive_authorization_endpoint").value("http://localhost:8090/v1/certify/oauth/iae"))
                .andExpect(jsonPath("$.require_interactive_authorization_request").value(true))
                .andExpect(jsonPath("$.jwks_uri").value("http://localhost:8090/v1/certify/oauth/.well-known/jwks.json"))
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported").doesNotExist());

        verify(oAuthAuthorizationServerMetadataService, times(1)).getOAuthAuthorizationServerMetadata();
    }

    @Test
    void processInteractiveAuthorizationRequest_success_requireInteraction() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback")
                .param("interaction_types_supported", "urn:openid:dcp:iae:openid4vp_presentation"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("require_interaction"))
                .andExpect(jsonPath("$.type").value("urn:openid:dcp:iae:openid4vp_presentation"))
                .andExpect(jsonPath("$.auth_session").value("test-session"))
                .andExpect(jsonPath("$.openid4vp_request.response_type").value("vp_token"))
                .andExpect(jsonPath("$.openid4vp_request.response_mode").value("iae_post.jwt"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_success_complete() throws Exception {
        // Arrange - Create a complete response (no interaction required)
        IarPresentationResponse mockResponse = new IarPresentationResponse();
        mockResponse.setStatus(IarStatus.OK);
        mockResponse.setAuthSession("test-session");
        // No type or openid4vp_request for complete responses
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.type").doesNotExist())
                .andExpect(jsonPath("$.openid4vp_request").doesNotExist());

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_minimalRequiredParams() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Only required parameters
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_withOptionalParams() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - All parameters including optional ones
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback")
                .param("interaction_types_supported", "urn:openid:dcp:iae:openid4vp_presentation"))
                .andExpect(status().isOk());

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_validationFailure() throws Exception {
        // Arrange - Test with missing required parameters to trigger validation failure
        // This test should trigger @ValidIar validation failure at Spring level

        // Act & Assert - Missing code_challenge should cause validation to fail
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isBadRequest()); // Validation failure should return 400 Bad Request

        // The service should not be called if validation fails
        verify(iarService, never()).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_processingFailure() throws Exception {
        // Arrange
        CertifyException processingException = new CertifyException("interaction_required", "Interaction required");
        doThrow(processingException).when(iarService).handleIarRequest(any(IarRequest.class));

        // Act & Assert
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("interaction_required"))
                .andExpect(jsonPath("$.error_description").value("Interaction required"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_unexpectedException() throws Exception {
        // Arrange
        RuntimeException unexpectedException = new RuntimeException("Unexpected error");
        doThrow(unexpectedException).when(iarService).handleIarRequest(any(IarRequest.class));

        // Act & Assert
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("server_error"))
                .andExpect(jsonPath("$.error_description").value("Internal server error"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_differentcode_challenge_methods() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Test S256 method
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge-s256")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        // Test S256 method again (plain method removed for security)
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge-s256-2")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        verify(iarService, times(2)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_differentResponseTypes() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Test with code response type
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        // Test with vp_token response type
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "vp_token")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        verify(iarService, times(2)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_contentTypeValidation() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Should accept form-urlencoded content type
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    // ==================== ADDITIONAL FIRST IAR CALL TESTS ====================

    // Note: Service-level exception tests are removed because validation happens at Spring level 
    // before service is called. The @ValidIar validation constraints prevent testing service-level exceptions.

    @Test
    void processInteractiveAuthorizationRequest_withAuthorizationDetails_success() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Test with authorization details
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback")
                .param("interaction_types_supported", "urn:openid:dcp:iae:openid4vp_presentation"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("require_interaction"))
                .andExpect(jsonPath("$.type").value("urn:openid:dcp:iae:openid4vp_presentation"))
                .andExpect(jsonPath("$.auth_session").value("test-session"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_emptyclient_id_success() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Test with empty client_id (public client)
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "") // Empty client ID
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_missingredirect_uri_success() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Test without redirect_uri (optional parameter)
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("require_interaction"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_missinginteraction_types_supported_success() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Test without interaction_types_supported (optional parameter)
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("require_interaction"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processTokenRequest_invalidGrant_returnsOAuthError() throws Exception {
        // Arrange
        CertifyException certifyException = new CertifyException("invalid_grant", "Authorization code expired");
        when(iarService.processTokenRequest(any())).thenThrow(certifyException);

        // Act & Assert
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "invalid-code")
                .param("redirect_uri", "https://test.com/callback")
                .param("client_id", "test-client")
                .param("code_verifier", "test-verifier"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.error_description").value("Authorization code expired"));

        verify(iarService, times(1)).processTokenRequest(any());
    }

    @Test
    void processTokenRequest_invalidClient_returnsOAuthError() throws Exception {
        // Arrange
        CertifyException certifyException = new CertifyException("invalid_client", "Client authentication failed");
        when(iarService.processTokenRequest(any())).thenThrow(certifyException);

        // Act & Assert
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "test-code")
                .param("redirect_uri", "https://test.com/callback")
                .param("client_id", "invalid-client")
                .param("code_verifier", "test-verifier"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").value("Client authentication failed"));

        verify(iarService, times(1)).processTokenRequest(any());
    }

    @Test
    void processTokenRequest_missingCode_returnsBadRequest() throws Exception {
        // Act & Assert - Missing code parameter should cause validation failure
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("redirect_uri", "https://test.com/callback")
                .param("client_id", "test-client")
                .param("code_verifier", "test-verifier"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("code is required"));

        verify(iarService, never()).processTokenRequest(any());
    }

    @Test
    void processTokenRequest_missingCodeVerifier_returnsBadRequest() throws Exception {
        // Act & Assert - Missing code_verifier parameter should cause validation failure
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "test-code")
                .param("redirect_uri", "https://test.com/callback")
                .param("client_id", "test-client"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("code_verifier is required"));

        verify(iarService, never()).processTokenRequest(any());
    }

    @Test
    void processTokenRequest_emptyCode_returnsBadRequest() throws Exception {
        // Act & Assert - Empty code parameter should cause validation failure
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "")
                .param("redirect_uri", "https://test.com/callback")
                .param("client_id", "test-client")
                .param("code_verifier", "test-verifier"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("code is required"));

        verify(iarService, never()).processTokenRequest(any());
    }

    @Test
    void processTokenRequest_emptyCodeVerifier_returnsBadRequest() throws Exception {
        // Act & Assert - Empty code_verifier parameter should cause validation failure
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "test-code")
                .param("redirect_uri", "https://test.com/callback")
                .param("client_id", "test-client")
                .param("code_verifier", ""))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("code_verifier is required"));

        verify(iarService, never()).processTokenRequest(any());
    }

    @Test
    void processTokenRequest_invalidAuthorizationCode_returnsInvalidGrant() throws Exception {
        // Arrange - Test with an explicitly invalid/expired authorization code
        CertifyException certifyException = new CertifyException("invalid_grant", "Authorization code not found or expired");
        when(iarService.processTokenRequest(any())).thenThrow(certifyException);

        // Act & Assert
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "iar_auth_invalid_or_expired_code")
                .param("redirect_uri", "https://test.com/callback")
                .param("client_id", "test-client")
                .param("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.error_description").value("Authorization code not found or expired"));

        verify(iarService, times(1)).processTokenRequest(any());
    }

    @Test
    void processTokenRequest_unsupportedGrantType_returnsInvalidRequest() throws Exception {
        // Act & Assert - Unsupported grant_type should cause validation failure
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "unsupported_grant_type")
                .param("code", "test-code")
                .param("redirect_uri", "https://test.com/callback")
                .param("client_id", "test-client")
                .param("code_verifier", "test-verifier"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("Unsupported or invalid grant_type"));

        verify(iarService, never()).processTokenRequest(any());
    }

    @Test
    void processTokenRequest_missingGrantType_returnsInvalidRequest() throws Exception {
        // Act & Assert - Missing grant_type should cause validation failure
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("code", "test-code")
                .param("redirect_uri", "https://test.com/callback")
                .param("client_id", "test-client")
                .param("code_verifier", "test-verifier"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("grant_type is required"));

        verify(iarService, never()).processTokenRequest(any());
    }

    // ==================== SECOND IAR CALL (VP PRESENTATION) TESTS ====================

    @Test
    void processVpPresentation_success_returnsAuthorizationCode() throws Exception {
        // Arrange - Mock successful VP presentation response
        IarAuthorizationResponse mockResponse = createMockIarAuthorizationResponse(IarStatus.OK, "iar_auth_test123456789");
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "test-session-123")
                .param("openid4vp_response", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.code").value("iar_auth_test123456789"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_vpVerificationFailed_returnsError() throws Exception {
        // Arrange - Mock VP verification failure response
        IarAuthorizationResponse mockResponse = createMockIarAuthorizationResponse(IarStatus.ERROR, null);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "test-session-123")
                .param("openid4vp_response", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("error"))
                .andExpect(jsonPath("$.code").doesNotExist());

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_missingauth_session_returnsBadRequest() throws Exception {
        // Act & Assert - Missing auth_session should cause validation failure
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("openid4vp_response", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."))
                .andExpect(status().isBadRequest());

        // The service should not be called if validation fails
        verify(iarService, never()).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_missingVpPresentation_returnsBadRequest() throws Exception {
        // Act & Assert - Missing openid4vp_response should cause validation failure
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "test-session-123"))
                .andExpect(status().isBadRequest());

        // The service should not be called if validation fails
        verify(iarService, never()).handleIarRequest(any(IarRequest.class));
    }

    // Note: Service-level exception tests are removed because validation happens at Spring level 
    // before service is called. The @ValidIar validation constraints prevent testing service-level exceptions.

    @Test
    void processVpPresentation_unexpectedException_returnsInternalServerError() throws Exception {
        // Arrange
        RuntimeException unexpectedException = new RuntimeException("Unexpected error during VP processing");
        when(iarService.handleIarRequest(any(IarRequest.class))).thenThrow(unexpectedException);

        // Act & Assert
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "test-session-123")
                .param("openid4vp_response", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("server_error"))
                .andExpect(jsonPath("$.error_description").value("Internal server error"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_withJwtVpToken_success() throws Exception {
        // Arrange
        IarAuthorizationResponse mockResponse = createMockIarAuthorizationResponse(IarStatus.OK, "iar_auth_jwt123456789");
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Test with JWT VP token
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "test-session-jwt")
                .param("openid4vp_response", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3YWxsZXQiLCJhdWQiOiJ2ZXJpZmllciIsInN1YiI6InRlc3QtdXNlciJ9.signature"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.code").value("iar_auth_jwt123456789"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_withJsonVpToken_success() throws Exception {
        // Arrange
        IarAuthorizationResponse mockResponse = createMockIarAuthorizationResponse(IarStatus.OK, "iar_auth_json123456789");
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Test with JSON VP token
        String jsonVpPresentation = "{\"vp_token\":{\"type\":\"VerifiablePresentation\",\"verifiableCredential\":[]}}";
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "test-session-json")
                .param("openid4vp_response", jsonVpPresentation))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.code").value("iar_auth_json123456789"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    // Note: Service-level exception tests are removed because validation happens at Spring level 
    // before service is called. The @ValidIar validation constraints prevent testing service-level exceptions.

    @Test
    void processVpPresentation_contentTypeValidation() throws Exception {
        // Arrange
        IarAuthorizationResponse mockResponse = createMockIarAuthorizationResponse(IarStatus.OK, "iar_auth_test123456789");
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Should accept form-urlencoded content type for VP presentation
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "test-session-123")
                .param("openid4vp_response", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_emptyauth_session_returnsBadRequest() throws Exception {
        // Act & Assert - Empty auth_session should cause validation failure
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "")
                .param("openid4vp_response", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."))
                .andExpect(status().isBadRequest());

        verify(iarService, never()).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_emptyVpPresentation_returnsBadRequest() throws Exception {
        // Act & Assert - Empty openid4vp_response should cause validation failure
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "test-session-123")
                .param("openid4vp_response", ""))
                .andExpect(status().isBadRequest());

        verify(iarService, never()).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_whitespaceOnlyParams_returnsBadRequest() throws Exception {
        // Act & Assert - Whitespace-only parameters should cause validation failure
        mockMvc.perform(post("/oauth/iae")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "   ")
                .param("openid4vp_response", "   "))
                .andExpect(status().isBadRequest());

        verify(iarService, never()).handleIarRequest(any(IarRequest.class));
    }

    /**
     * Helper method to create a mock IAR response
     */
    private IarResponse createMockIarResponse(IarStatus status) {
        IarPresentationResponse response = new IarPresentationResponse();
        response.setStatus(status);
        response.setAuthSession("test-session");
        
        if (IarStatus.REQUIRE_INTERACTION.equals(status)) {
            response.setType(InteractionType.OPENID4VP_PRESENTATION);
            
            Map<String, Object> openId4VpRequest = new HashMap<>();
            openId4VpRequest.put("response_type", "vp_token");
            openId4VpRequest.put("response_mode", "iae_post.jwt");
            openId4VpRequest.put("client_id", "test-client");
            
            Map<String, Object> dcqlQuery = new HashMap<>();
            dcqlQuery.put("credentials", List.of(Map.of(
                    "id", "mosip_verifiable_credential_id",
                    "format", "ldp_vc"
            )));
            openId4VpRequest.put("dcql_query", dcqlQuery);
            
            response.setOpenid4vpRequest(openId4VpRequest);
        }
        
        return response;
    }


    /**
     * Helper method to create a mock IAR authorization response for VP presentation
     */
    private IarAuthorizationResponse createMockIarAuthorizationResponse(IarStatus status, String authorizationCode) {
        IarAuthorizationResponse response = new IarAuthorizationResponse();
        response.setStatus(status);
        response.setCode(authorizationCode);
        return response;
    }
}
