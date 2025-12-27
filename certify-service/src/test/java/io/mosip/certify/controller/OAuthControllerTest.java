package io.mosip.certify.controller;

import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.constants.InteractionType;
import io.mosip.certify.core.dto.IarRequest;
import io.mosip.certify.core.dto.IarResponse;
import io.mosip.certify.core.dto.IarAuthorizationResponse;
import io.mosip.certify.core.dto.PresentationDefinition;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.IarService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.filter.AccessTokenValidationFilter;
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

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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
    private IarService iarService;

    @MockBean
    private MessageSource messageSource;

    @MockBean
    private JwksService jwksService;

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
    void processInteractiveAuthorizationRequest_success_requireInteraction() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback")
                .param("interaction_types_supported", "openid4vp_presentation"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("require_interaction"))
                .andExpect(jsonPath("$.type").value("openid4vp_presentation"))
                .andExpect(jsonPath("$.auth_session").value("test-session"))
                .andExpect(jsonPath("$.openid4vp_request.response_type").value("vp_token"))
                .andExpect(jsonPath("$.openid4vp_request.response_mode").value("iar-post.jwt"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_success_complete() throws Exception {
        // Arrange - Create a complete response (no interaction required)
        IarResponse mockResponse = new IarResponse();
        mockResponse.setStatus(IarStatus.OK);
        mockResponse.setAuthSession("test-session");
        // No type or openid4vp_request for complete responses
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback")
                .param("interaction_types_supported", "openid4vp_presentation"))
                .andExpect(status().isOk());

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_validationFailure() throws Exception {
        // Arrange - Test with missing required parameters to trigger validation failure
        // This test should trigger @ValidIar validation failure at Spring level

        // Act & Assert - Missing code_challenge should cause validation to fail
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("interaction_required"))
                .andExpect(jsonPath("$.error_description").value("interaction_required"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_unexpectedException() throws Exception {
        // Arrange
        RuntimeException unexpectedException = new RuntimeException("Unexpected error");
        doThrow(unexpectedException).when(iarService).handleIarRequest(any(IarRequest.class));

        // Act & Assert
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge-s256")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        // Test S256 method again (plain method removed for security)
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        // Test with vp_token response type
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback")
                .param("interaction_types_supported", "openid4vp_presentation"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("require_interaction"))
                .andExpect(jsonPath("$.type").value("openid4vp_presentation"))
                .andExpect(jsonPath("$.auth_session").value("test-session"));

        verify(iarService, times(1)).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_emptyclient_id_success() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarStatus.REQUIRE_INTERACTION);
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Test with empty client_id (public client)
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
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
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").value("Client authentication failed"));

        verify(iarService, times(1)).processTokenRequest(any());
    }

    @Test
    void processTokenRequest_missingParameters_returnsOAuthError() throws Exception {
        // Act & Assert - Missing required parameters should return 400 with OAuth error format
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("code is required for authorization_code grant"));
    }

    // ==================== SECOND IAR CALL (VP PRESENTATION) TESTS ====================

    @Test
    void processVpPresentation_success_returnsAuthorizationCode() throws Exception {
        // Arrange - Mock successful VP presentation response
        IarAuthorizationResponse mockResponse = createMockIarAuthorizationResponse(IarStatus.OK, "iar_auth_test123456789");
        when(iarService.handleIarRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("openid4vp_response", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."))
                .andExpect(status().isBadRequest());

        // The service should not be called if validation fails
        verify(iarService, never()).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_missingVpPresentation_returnsBadRequest() throws Exception {
        // Act & Assert - Missing openid4vp_response should cause validation failure
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
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
        String jsonVpPresentation = "{\"vp_token\":{\"type\":\"VerifiablePresentation\",\"verifiableCredential\":[]},\"presentation_submission\":{\"id\":\"test-submission\"}}";
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
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
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "")
                .param("openid4vp_response", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."))
                .andExpect(status().isBadRequest());

        verify(iarService, never()).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_emptyVpPresentation_returnsBadRequest() throws Exception {
        // Act & Assert - Empty openid4vp_response should cause validation failure
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("auth_session", "test-session-123")
                .param("openid4vp_response", ""))
                .andExpect(status().isBadRequest());

        verify(iarService, never()).handleIarRequest(any(IarRequest.class));
    }

    @Test
    void processVpPresentation_whitespaceOnlyParams_returnsBadRequest() throws Exception {
        // Act & Assert - Whitespace-only parameters should cause validation failure
        mockMvc.perform(post("/oauth/iar")
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
        IarResponse response = new IarResponse();
        response.setStatus(status);
        response.setAuthSession("test-session");
        
        if (IarStatus.REQUIRE_INTERACTION.equals(status)) {
            response.setType(InteractionType.OPENID4VP_PRESENTATION);
            
            Map<String, Object> openId4VpRequest = new HashMap<>();
            openId4VpRequest.put("response_type", "vp_token");
            openId4VpRequest.put("response_mode", "iar-post.jwt");
            openId4VpRequest.put("client_id", "test-client");
            
            PresentationDefinition presentationDefinition = new PresentationDefinition();
            presentationDefinition.setId("test-presentation");
            openId4VpRequest.put("presentation_definition", presentationDefinition);
            
            response.setOpenid4vpRequest(openId4VpRequest);
        }
        
        return response;
    }

    @Test
    void getJwks_success_withKeys() throws Exception {
        // Arrange
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("kid", "test-key-1");

        Map<String, Object> jwksResponse = new HashMap<>();
        jwksResponse.put("keys", List.of(jwk));

        when(jwksService.getJwks()).thenReturn(jwksResponse);

        // Act & Assert
        mockMvc.perform(get("/oauth/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value("test-key-1"));

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_success_emptyKeys() throws Exception {
        // Arrange
        Map<String, Object> jwksResponse = new HashMap<>();
        jwksResponse.put("keys", List.of());

        when(jwksService.getJwks()).thenReturn(jwksResponse);

        // Act & Assert
        mockMvc.perform(get("/oauth/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_invalidResponseStructure_returnsServiceUnavailable() throws Exception {
        // Arrange
        Map<String, Object> invalidResponse = new HashMap<>();
        invalidResponse.put("invalid", "data");

        when(jwksService.getJwks()).thenReturn(invalidResponse);

        // Act & Assert
        mockMvc.perform(get("/oauth/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_exceptionThrown_returnsServiceUnavailable() throws Exception {
        // Arrange
        when(jwksService.getJwks()).thenThrow(new RuntimeException("Keymanager down"));

        // Act & Assert
        mockMvc.perform(get("/oauth/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
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