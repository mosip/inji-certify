/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.constants.InteractionType;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.IarSessionRepository;
import io.mosip.certify.utils.AccessTokenJwtUtil;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class IarServiceImplTest {

    @Mock
    private IarSessionRepository iarSessionRepository;
    @Mock
    private IarPresentationService iarPresentationService;
    @Mock
    private IarSessionService iarSessionService;
    @Mock
    private IarVpRequestService iarVpRequestService;
    @Mock
    private AccessTokenJwtUtil accessTokenJwtUtil;
    @Mock
    private Validator validator;

    @InjectMocks
    private IarServiceImpl iarService;

    private static final String CODE_VERIFIER = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEF";
    private String codeChallenge;

    @Before
    public void setup() throws Exception {
        ReflectionTestUtils.setField(iarService, "tokenExpiresInSeconds", 3600);
        ReflectionTestUtils.setField(iarService, "cNonceExpiresInSeconds", 300);
        ReflectionTestUtils.setField(iarService, "authorizationCodeExpiresMinutes", 10);
        ReflectionTestUtils.setField(iarService, "tokenType", "Bearer");
        ReflectionTestUtils.setField(iarService, "issuer", "https://issuer");
        ReflectionTestUtils.setField(iarService, "audience", "https://audience");

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(CODE_VERIFIER.getBytes(StandardCharsets.UTF_8));
        codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private IarRequest validInitialRequest() {
        AuthorizationDetail detail = new AuthorizationDetail();
        detail.setType("openid_credential");
        detail.setCredentialConfigurationId("cred-config-1");

        IarRequest request = new IarRequest();
        request.setResponse_type("code");
        request.setClient_id("client-1");
        request.setCode_challenge("challenge");
        request.setCode_challenge_method("S256");
        request.setInteraction_types_supported(InteractionType.OPENID4VP_PRESENTATION.getValue());
        request.setAuthorization_details(List.of(detail));
        return request;
    }

    // ---------- handleIarRequest ----------

    @Test
    public void handleIarRequest_initial_generatesVpRequest() {
        when(iarSessionService.generateAuthSession()).thenReturn("auth-session-1");
        VerifyVpResponse verifyResponse = new VerifyVpResponse();
        verifyResponse.setTransactionId("txn-1");
        when(iarVpRequestService.createVpRequest(any())).thenReturn(verifyResponse);
        when(iarVpRequestService.convertToOpenId4VpRequest(any(), any())).thenReturn("{vp-request}");
        when(iarSessionService.createIarSession(any(), any(), anyString(), any())).thenReturn(new IarSession());

        Object result = iarService.handleIarRequest(validInitialRequest());

        assertTrue(result instanceof IarPresentationResponse);
        IarPresentationResponse response = (IarPresentationResponse) result;
        assertEquals(IarStatus.REQUIRE_INTERACTION, response.getStatus());
        assertEquals("auth-session-1", response.getAuthSession());
        verify(iarSessionRepository).save(any(IarSession.class));
    }

    @Test
    public void handleIarRequest_presentation_delegatesToPresentationService() {
        IarRequest request = new IarRequest();
        request.setAuth_session("auth-1");
        request.setOpenid4vp_response("{vp}");
        IarAuthorizationResponse presentationResult = new IarAuthorizationResponse();
        when(iarPresentationService.processVpPresentation(any())).thenReturn(presentationResult);

        Object result = iarService.handleIarRequest(request);

        assertSame(presentationResult, result);
    }

    @Test
    public void handleIarRequest_onlyAuthSession_throwsInvalidRequest() {
        IarRequest request = new IarRequest();
        request.setAuth_session("auth-1");
        assertThrows(InvalidRequestException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_onlyVp_throwsInvalidRequest() {
        IarRequest request = new IarRequest();
        request.setOpenid4vp_response("{vp}");
        assertThrows(InvalidRequestException.class, () -> iarService.handleIarRequest(request));
    }

    // ---------- validateIarRequest ----------

    @Test
    public void handleIarRequest_badResponseType_throws() {
        IarRequest request = validInitialRequest();
        request.setResponse_type("token");
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_missingClientId_throws() {
        IarRequest request = validInitialRequest();
        request.setClient_id("");
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_missingCodeChallenge_throws() {
        IarRequest request = validInitialRequest();
        request.setCode_challenge("");
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_badCodeChallengeMethod_throws() {
        IarRequest request = validInitialRequest();
        request.setCode_challenge_method("plain");
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_missingInteractionType_throws() {
        IarRequest request = validInitialRequest();
        request.setInteraction_types_supported("some_other_type");
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_emptyInteractionType_usesDefault() {
        IarRequest request = validInitialRequest();
        request.setInteraction_types_supported("");
        when(iarSessionService.generateAuthSession()).thenReturn("auth-session-1");
        VerifyVpResponse verifyResponse = new VerifyVpResponse();
        verifyResponse.setTransactionId("txn-1");
        when(iarVpRequestService.createVpRequest(any())).thenReturn(verifyResponse);
        when(iarVpRequestService.convertToOpenId4VpRequest(any(), any())).thenReturn("{vp-request}");
        when(iarSessionService.createIarSession(any(), any(), anyString(), any())).thenReturn(new IarSession());

        Object result = iarService.handleIarRequest(request);
        assertTrue(result instanceof IarPresentationResponse);
    }

    @Test
    public void handleIarRequest_missingAuthorizationDetails_throws() {
        IarRequest request = validInitialRequest();
        request.setAuthorization_details(Collections.emptyList());
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_authDetailMissingType_throws() {
        IarRequest request = validInitialRequest();
        AuthorizationDetail detail = new AuthorizationDetail();
        detail.setCredentialConfigurationId("cred-config-1");
        request.setAuthorization_details(List.of(detail));
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_authDetailWrongType_throws() {
        IarRequest request = validInitialRequest();
        AuthorizationDetail detail = new AuthorizationDetail();
        detail.setType("wrong_type");
        detail.setCredentialConfigurationId("cred-config-1");
        request.setAuthorization_details(List.of(detail));
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_authDetailMissingConfigId_throws() {
        IarRequest request = validInitialRequest();
        AuthorizationDetail detail = new AuthorizationDetail();
        detail.setType("openid_credential");
        request.setAuthorization_details(List.of(detail));
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(request));
    }

    @Test
    public void handleIarRequest_vpRequestGenerationFails_throws() {
        when(iarSessionService.generateAuthSession()).thenReturn("auth-session-1");
        when(iarVpRequestService.createVpRequest(any())).thenThrow(new RuntimeException("verify down"));
        assertThrows(CertifyException.class, () -> iarService.handleIarRequest(validInitialRequest()));
    }

    // ---------- processTokenRequest ----------

    private OAuthTokenRequest validTokenRequest() {
        OAuthTokenRequest request = new OAuthTokenRequest();
        request.setGrant_type("authorization_code");
        request.setCode("iar_auth_abc123");
        request.setCode_verifier(CODE_VERIFIER);
        return request;
    }

    private IarSession sessionForToken() {
        IarSession session = new IarSession();
        session.setAuthorizationCode("iar_auth_abc123");
        session.setCodeChallenge(codeChallenge);
        session.setCodeChallengeMethod("S256");
        session.setIsCodeUsed(false);
        session.setCodeIssuedAt(LocalDateTime.now());
        session.setScope("test_scope");
        session.setClientId("client-1");
        return session;
    }

    @Test
    public void processTokenRequest_success() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        when(iarSessionRepository.findByAuthorizationCode("iar_auth_abc123"))
                .thenReturn(Optional.of(sessionForToken()));
        when(iarSessionRepository.markAuthorizationCodeAsUsed(anyString(), any())).thenReturn(1);
        when(accessTokenJwtUtil.generateSignedJwt(any(IarSession.class), anyString(), anyString(), anyInt()))
                .thenReturn("signed.jwt");

        OAuthTokenResponse response = iarService.processTokenRequest(validTokenRequest());

        assertEquals("signed.jwt", response.getAccessToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(3600, response.getExpiresIn().intValue());
        assertEquals("test_scope", response.getScope());
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    public void processTokenRequest_constraintViolations_throws() {
        ConstraintViolation<OAuthTokenRequest> violation = mock(ConstraintViolation.class);
        java.util.Set violations = new java.util.HashSet();
        violations.add(violation);
        doReturn(violations).when(validator).validate(any());
        assertThrows(ConstraintViolationException.class,
                () -> iarService.processTokenRequest(validTokenRequest()));
    }

    @Test
    public void processTokenRequest_unsupportedGrantType_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        OAuthTokenRequest request = validTokenRequest();
        request.setGrant_type("client_credentials");
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(request));
    }

    @Test
    public void processTokenRequest_missingCode_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        OAuthTokenRequest request = validTokenRequest();
        request.setCode("");
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(request));
    }

    @Test
    public void processTokenRequest_badCodePrefix_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        OAuthTokenRequest request = validTokenRequest();
        request.setCode("wrong_prefix_code");
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(request));
    }

    @Test
    public void processTokenRequest_codeNotFound_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        when(iarSessionRepository.findByAuthorizationCode(anyString())).thenReturn(Optional.empty());
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(validTokenRequest()));
    }

    @Test
    public void processTokenRequest_codeAlreadyUsed_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        IarSession session = sessionForToken();
        session.setIsCodeUsed(true);
        when(iarSessionRepository.findByAuthorizationCode(anyString())).thenReturn(Optional.of(session));
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(validTokenRequest()));
    }

    @Test
    public void processTokenRequest_codeExpired_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        IarSession session = sessionForToken();
        session.setCodeIssuedAt(LocalDateTime.now().minusMinutes(30));
        when(iarSessionRepository.findByAuthorizationCode(anyString())).thenReturn(Optional.of(session));
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(validTokenRequest()));
    }

    @Test
    public void processTokenRequest_missingCodeVerifier_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        when(iarSessionRepository.findByAuthorizationCode(anyString())).thenReturn(Optional.of(sessionForToken()));
        OAuthTokenRequest request = validTokenRequest();
        request.setCode_verifier("");
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(request));
    }

    @Test
    public void processTokenRequest_missingPkceInSession_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        IarSession session = sessionForToken();
        session.setCodeChallenge(null);
        when(iarSessionRepository.findByAuthorizationCode(anyString())).thenReturn(Optional.of(session));
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(validTokenRequest()));
    }

    @Test
    public void processTokenRequest_pkceMismatch_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        IarSession session = sessionForToken();
        session.setCodeChallenge("some_other_challenge");
        when(iarSessionRepository.findByAuthorizationCode(anyString())).thenReturn(Optional.of(session));
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(validTokenRequest()));
    }

    @Test
    public void processTokenRequest_markAsUsedReturnsZero_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        when(iarSessionRepository.findByAuthorizationCode(anyString())).thenReturn(Optional.of(sessionForToken()));
        when(iarSessionRepository.markAuthorizationCodeAsUsed(anyString(), any())).thenReturn(0);
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(validTokenRequest()));
    }

    @Test
    public void processTokenRequest_tokenGenerationFails_throws() {
        when(validator.validate(any())).thenReturn(Collections.emptySet());
        when(iarSessionRepository.findByAuthorizationCode(anyString())).thenReturn(Optional.of(sessionForToken()));
        when(iarSessionRepository.markAuthorizationCodeAsUsed(anyString(), any())).thenReturn(1);
        when(accessTokenJwtUtil.generateSignedJwt(any(IarSession.class), anyString(), anyString(), anyInt()))
                .thenThrow(new RuntimeException("kms down"));
        assertThrows(CertifyException.class, () -> iarService.processTokenRequest(validTokenRequest()));
    }
}
