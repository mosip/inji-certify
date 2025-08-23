package io.mosip.certify.controller;

import io.mosip.certify.core.constants.IarConstants;
import io.mosip.certify.core.dto.IarRequest;
import io.mosip.certify.core.dto.IarResponse;
import io.mosip.certify.core.dto.OpenId4VpRequest;
import io.mosip.certify.core.dto.PresentationDefinition;
import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.IarService;
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

import java.util.Locale;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for OAuthAuthorizationController
 * Tests the Interactive Authorization Request (IAR) endpoint functionality
 */
@WebMvcTest(value = OAuthAuthorizationController.class, 
             excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, 
                                                  classes = {AccessTokenValidationFilter.class}))
class OAuthAuthorizationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IarService iarService;

    @MockBean
    private MessageSource messageSource;

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
        IarResponse mockResponse = createMockIarResponse(IarConstants.STATUS_REQUIRE_INTERACTION);
        when(iarService.processAuthorizationRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback")
                .param("interaction_types_supported", "openid4vp_presentation")
                .param("scope", "openid")
                .param("state", "test-state"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(IarConstants.STATUS_REQUIRE_INTERACTION))
                .andExpect(jsonPath("$.type").value(IarConstants.TYPE_OPENID4VP_PRESENTATION))
                .andExpect(jsonPath("$.auth_session").value("test-session"))
                .andExpect(jsonPath("$.openid4vp_request.response_type").value("vp_token"))
                .andExpect(jsonPath("$.openid4vp_request.response_mode").value("iar-post.jwt"));

        verify(iarService, times(1)).validateIarRequest(any(IarRequest.class));
        verify(iarService, times(1)).processAuthorizationRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_success_complete() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarConstants.STATUS_COMPLETE);
        when(iarService.processAuthorizationRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(IarConstants.STATUS_COMPLETE))
                .andExpect(jsonPath("$.type").doesNotExist())
                .andExpect(jsonPath("$.openid4vp_request").doesNotExist());

        verify(iarService, times(1)).validateIarRequest(any(IarRequest.class));
        verify(iarService, times(1)).processAuthorizationRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_minimalRequiredParams() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarConstants.STATUS_REQUIRE_INTERACTION);
        when(iarService.processAuthorizationRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - Only required parameters
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        verify(iarService, times(1)).validateIarRequest(any(IarRequest.class));
        verify(iarService, times(1)).processAuthorizationRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_withOptionalParams() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarConstants.STATUS_REQUIRE_INTERACTION);
        when(iarService.processAuthorizationRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Act & Assert - All parameters including optional ones
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback")
                .param("interaction_types_supported", "openid4vp_presentation")
                .param("redirect_to_web", "true")
                .param("scope", "openid profile")
                .param("state", "custom-state"))
                .andExpect(status().isOk());

        verify(iarService, times(1)).validateIarRequest(any(IarRequest.class));
        verify(iarService, times(1)).processAuthorizationRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_validationFailure() throws Exception {
        // Arrange
        CertifyException validationException = new CertifyException(IarConstants.INVALID_REQUEST, "invalid_request");
        doThrow(validationException).when(iarService).validateIarRequest(any(IarRequest.class));

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
                .andExpect(jsonPath("$.error").value(IarConstants.INVALID_REQUEST))
                .andExpect(jsonPath("$.error_description").value("invalid_request"));

        verify(iarService, times(1)).validateIarRequest(any(IarRequest.class));
        verify(iarService, never()).processAuthorizationRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_processingFailure() throws Exception {
        // Arrange
        CertifyException processingException = new CertifyException(IarConstants.INTERACTION_REQUIRED, "Interaction required");
        doNothing().when(iarService).validateIarRequest(any(IarRequest.class));
        doThrow(processingException).when(iarService).processAuthorizationRequest(any(IarRequest.class));

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
                .andExpect(jsonPath("$.error").value(IarConstants.INTERACTION_REQUIRED))
                .andExpect(jsonPath("$.error_description").value("interaction_required"));

        verify(iarService, times(1)).validateIarRequest(any(IarRequest.class));
        verify(iarService, times(1)).processAuthorizationRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_unexpectedException() throws Exception {
        // Arrange
        RuntimeException unexpectedException = new RuntimeException("Unexpected error");
        doNothing().when(iarService).validateIarRequest(any(IarRequest.class));
        doThrow(unexpectedException).when(iarService).processAuthorizationRequest(any(IarRequest.class));

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
                .andExpect(jsonPath("$.error").value(IarConstants.INVALID_REQUEST))
                .andExpect(jsonPath("$.error_description").value("invalid_request"));

        verify(iarService, times(1)).validateIarRequest(any(IarRequest.class));
        verify(iarService, times(1)).processAuthorizationRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_differentCodeChallengeMethods() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarConstants.STATUS_REQUIRE_INTERACTION);
        when(iarService.processAuthorizationRequest(any(IarRequest.class))).thenReturn(mockResponse);

        // Test S256 method
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge-s256")
                .param("code_challenge_method", "S256")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        // Test plain method
        mockMvc.perform(post("/oauth/iar")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("code_challenge", "test-challenge-plain")
                .param("code_challenge_method", "plain")
                .param("redirect_uri", "https://test.com/callback"))
                .andExpect(status().isOk());

        verify(iarService, times(2)).validateIarRequest(any(IarRequest.class));
        verify(iarService, times(2)).processAuthorizationRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_differentResponseTypes() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarConstants.STATUS_REQUIRE_INTERACTION);
        when(iarService.processAuthorizationRequest(any(IarRequest.class))).thenReturn(mockResponse);

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

        verify(iarService, times(2)).validateIarRequest(any(IarRequest.class));
        verify(iarService, times(2)).processAuthorizationRequest(any(IarRequest.class));
    }

    @Test
    void processInteractiveAuthorizationRequest_contentTypeValidation() throws Exception {
        // Arrange
        IarResponse mockResponse = createMockIarResponse(IarConstants.STATUS_REQUIRE_INTERACTION);
        when(iarService.processAuthorizationRequest(any(IarRequest.class))).thenReturn(mockResponse);

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

        verify(iarService, times(1)).validateIarRequest(any(IarRequest.class));
        verify(iarService, times(1)).processAuthorizationRequest(any(IarRequest.class));
    }

    /**
     * Helper method to create a mock IAR response
     */
    private IarResponse createMockIarResponse(String status) {
        IarResponse response = new IarResponse();
        response.setStatus(status);
        response.setAuthSession("test-session");
        
        if (IarConstants.STATUS_REQUIRE_INTERACTION.equals(status)) {
            response.setType(IarConstants.TYPE_OPENID4VP_PRESENTATION);
            
            OpenId4VpRequest openId4VpRequest = new OpenId4VpRequest();
            openId4VpRequest.setResponseType("vp_token");
            openId4VpRequest.setResponseMode("iar-post.jwt");
            openId4VpRequest.setClientId("test-client");
            openId4VpRequest.setNonce("test-nonce");
            openId4VpRequest.setState("test-state");
            
            PresentationDefinition presentationDefinition = new PresentationDefinition();
            presentationDefinition.setId("test-presentation");
            openId4VpRequest.setPresentationDefinition(presentationDefinition);
            
            response.setOpenid4vpRequest(openId4VpRequest);
        }
        
        return response;
    }
}
