/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.dto.result.CredentialResultsDto;
import io.inji.verify.dto.result.VPVerificationResultDto;
import io.inji.verify.dto.result.VerificationRequestDto;
import io.inji.verify.services.VerifiablePresentationSubmissionService;
import io.mosip.certify.core.constants.IarStatus;
import io.mosip.certify.core.dto.IarAuthorizationRequest;
import io.mosip.certify.core.dto.IarAuthorizationResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.IarSessionRepository;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link IarPresentationService} covering the DCQL migration paths:
 *  - No presentation_submission required or forwarded on submit
 *  - New getVPResultV2(VerificationRequestDto, transactionId) flow with includeClaims=true
 *  - Missing vp_token, submission-library failure, missing identity, invalid auth_session
 *  - Successful and failed verification branches
 */
@RunWith(MockitoJUnitRunner.class)
public class IarPresentationServiceTest {

    @Mock
    private IarSessionRepository iarSessionRepository;

    @Mock
    private VerifiablePresentationSubmissionService vpSubmissionService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @InjectMocks
    private IarPresentationService iarPresentationService;

    private IarSession session;

    @Before
    public void setUp() {
        ReflectionTestUtils.setField(iarPresentationService, "objectMapper", objectMapper);
        ReflectionTestUtils.setField(iarPresentationService, "authorizationCodeLength", 24);
        ReflectionTestUtils.setField(iarPresentationService, "identityKeys",
                new HashSet<>(Arrays.asList("uin", "vid", "UIN", "UID")));

        session = new IarSession();
        session.setAuthSession("auth-session-123");
        session.setRequestId("req-1");
        session.setTransactionId("txn-1");
        session.setResponseUri("https://certify.example/iae");
    }

    private IarAuthorizationRequest requestWithVpToken(String vpToken) {
        IarAuthorizationRequest req = new IarAuthorizationRequest();
        req.setAuthSession("auth-session-123");
        Map<String, Object> presentation = new HashMap<>();
        presentation.put("vp_token", vpToken);
        try {
            req.setOpenid4vpPresentation(objectMapper.writeValueAsString(presentation));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return req;
    }

    private IarAuthorizationRequest requestWithDcqlMap(Map<String, Object> vpTokenMap) {
        IarAuthorizationRequest req = new IarAuthorizationRequest();
        req.setAuthSession("auth-session-123");
        Map<String, Object> presentation = new HashMap<>();
        presentation.put("vp_token", vpTokenMap);
        try {
            req.setOpenid4vpPresentation(objectMapper.writeValueAsString(presentation));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return req;
    }

    private VPVerificationResultDto successVpResult(String vcJson) {
        VPVerificationResultDto vpResult = new VPVerificationResultDto();
        vpResult.setAllChecksSuccessful(true);
        vpResult.setTransactionId("txn-1");
        CredentialResultsDto cr = new CredentialResultsDto();
        cr.setAllChecksSuccessful(true);
        cr.setVerifiableCredential(vcJson);
        vpResult.setCredentialResults(Collections.singletonList(cr));
        return vpResult;
    }

    // -----------------------------------------------------------------------
    // Successful flow — issues authorization code, forwards vp_token without PS
    // -----------------------------------------------------------------------
    @Test
    public void processVpPresentation_success_generatesAuthorizationCode() throws Exception {
        String vcJson = "{\"credentialSubject\":{\"uin\":\"1234567890\"}}";
        when(iarSessionRepository.findByAuthSession("auth-session-123"))
                .thenReturn(Optional.of(session));
        when(vpSubmissionService.getVPResultV2(any(VerificationRequestDto.class), eq("txn-1")))
                .thenReturn(successVpResult(vcJson));

        IarAuthorizationRequest req = requestWithVpToken("eyJhbGciOi.jwt.token");
        IarAuthorizationResponse resp = iarPresentationService.processVpPresentation(req);

        Assert.assertEquals(IarStatus.OK, resp.getStatus());
        Assert.assertNotNull(resp.getCode());
        Assert.assertTrue(resp.getCode().startsWith("iar_auth_"));

        // Removal of presentation_submission — verify only vp_token + state passed
        verify(vpSubmissionService).submitVerifiablePresentation(
                eq("eyJhbGciOi.jwt.token"), eq("req-1"), isNull(), isNull(), eq(Optional.empty()));

        // getVPResultV2 called with includeClaims=true
        ArgumentCaptor<VerificationRequestDto> vrCap = ArgumentCaptor.forClass(VerificationRequestDto.class);
        verify(vpSubmissionService).getVPResultV2(vrCap.capture(), eq("txn-1"));
        Assert.assertTrue(vrCap.getValue().isIncludeClaims());

        // Session persisted with identity + auth code
        ArgumentCaptor<IarSession> sessionCap = ArgumentCaptor.forClass(IarSession.class);
        verify(iarSessionRepository, atLeastOnce()).save(sessionCap.capture());
        Assert.assertEquals("1234567890", sessionCap.getAllValues().get(0).getIdentityData());
    }

    // -----------------------------------------------------------------------
    // DCQL vp_token as JSON object is serialised and forwarded intact
    // -----------------------------------------------------------------------
    @Test
    public void processVpPresentation_dcqlObjectVpToken_forwardedAsJson() throws Exception {
        Map<String, Object> vpTokenMap = new LinkedHashMap<>();
        vpTokenMap.put("mosip_verifiable_credential_id", Collections.singletonList("eyJ.jwt.a"));
        vpTokenMap.put("second_cred_id", Collections.singletonList("eyJ.jwt.b"));

        when(iarSessionRepository.findByAuthSession("auth-session-123"))
                .thenReturn(Optional.of(session));
        when(vpSubmissionService.getVPResultV2(any(VerificationRequestDto.class), eq("txn-1")))
                .thenReturn(successVpResult("{\"credentialSubject\":{\"UIN\":\"999\"}}"));

        iarPresentationService.processVpPresentation(requestWithDcqlMap(vpTokenMap));

        ArgumentCaptor<String> vpTokenCap = ArgumentCaptor.forClass(String.class);
        verify(vpSubmissionService).submitVerifiablePresentation(
                vpTokenCap.capture(), eq("req-1"), isNull(), isNull(), eq(Optional.empty()));
        // Whole DCQL map forwarded intact (not flattened)
        String forwarded = vpTokenCap.getValue();
        Assert.assertTrue(forwarded.contains("mosip_verifiable_credential_id"));
        Assert.assertTrue(forwarded.contains("second_cred_id"));
    }

    // -----------------------------------------------------------------------
    // Missing vp_token in presentation → vp_submission_failed
    // -----------------------------------------------------------------------
    @Test
    public void processVpPresentation_missingVpToken_throwsVpSubmissionFailed() throws Exception {
        when(iarSessionRepository.findByAuthSession("auth-session-123"))
                .thenReturn(Optional.of(session));

        IarAuthorizationRequest req = new IarAuthorizationRequest();
        req.setAuthSession("auth-session-123");
        req.setOpenid4vpPresentation("{}");

        try {
            iarPresentationService.processVpPresentation(req);
            Assert.fail("Expected CertifyException");
        } catch (CertifyException e) {
            Assert.assertEquals("vp_submission_failed", e.getErrorCode());
            Assert.assertTrue(e.getMessage() == null || e.getMessage().contains("Missing vp_token"));
        }
        verify(vpSubmissionService, never()).submitVerifiablePresentation(
                anyString(), anyString(), any(), any(), any());
    }

    // -----------------------------------------------------------------------
    // verify-core library throws → wrapped as vp_submission_failed
    // -----------------------------------------------------------------------
    @Test
    public void processVpPresentation_librarySubmissionThrows_wrapsAsVpSubmissionFailed() throws Exception {
        when(iarSessionRepository.findByAuthSession("auth-session-123"))
                .thenReturn(Optional.of(session));
        doThrow(new RuntimeException("invalid vp"))
                .when(vpSubmissionService).submitVerifiablePresentation(
                        anyString(), anyString(), any(), any(), any());

        try {
            iarPresentationService.processVpPresentation(requestWithVpToken("some.jwt"));
            Assert.fail("Expected CertifyException");
        } catch (CertifyException e) {
            Assert.assertEquals("vp_submission_failed", e.getErrorCode());
        }
        verify(vpSubmissionService, never())
                .getVPResultV2(any(VerificationRequestDto.class), anyString());
    }

    // -----------------------------------------------------------------------
    // Verification failure → status=ERROR, no code
    // -----------------------------------------------------------------------
    @Test
    public void processVpPresentation_verificationFailed_returnsErrorStatus() throws Exception {
        when(iarSessionRepository.findByAuthSession("auth-session-123"))
                .thenReturn(Optional.of(session));
        VPVerificationResultDto vpResult = new VPVerificationResultDto();
        vpResult.setAllChecksSuccessful(false);
        vpResult.setCredentialResults(Collections.emptyList());
        when(vpSubmissionService.getVPResultV2(any(VerificationRequestDto.class), eq("txn-1")))
                .thenReturn(vpResult);

        IarAuthorizationResponse resp = iarPresentationService.processVpPresentation(
                requestWithVpToken("some.jwt"));

        Assert.assertEquals(IarStatus.ERROR, resp.getStatus());
        Assert.assertNull(resp.getCode());
        verify(iarSessionRepository, never()).save(any(IarSession.class));
    }

    // -----------------------------------------------------------------------
    // Identity not extractable → invalid_vp
    // -----------------------------------------------------------------------
    @Test
    public void processVpPresentation_missingIdentity_throwsInvalidVp() throws Exception {
        when(iarSessionRepository.findByAuthSession("auth-session-123"))
                .thenReturn(Optional.of(session));
        String vcWithoutIdentity = "{\"credentialSubject\":{\"name\":\"alice\"}}";
        when(vpSubmissionService.getVPResultV2(any(VerificationRequestDto.class), eq("txn-1")))
                .thenReturn(successVpResult(vcWithoutIdentity));

        try {
            iarPresentationService.processVpPresentation(requestWithVpToken("some.jwt"));
            Assert.fail("Expected CertifyException(invalid_vp)");
        } catch (CertifyException e) {
            Assert.assertEquals("invalid_vp", e.getErrorCode());
        }
    }

    // -----------------------------------------------------------------------
    // Invalid auth_session → INVALID_REQUEST
    // -----------------------------------------------------------------------
    @Test
    public void processVpPresentation_invalidAuthSession_throwsInvalidRequest() {
        when(iarSessionRepository.findByAuthSession("auth-session-123"))
                .thenReturn(Optional.empty());

        try {
            iarPresentationService.processVpPresentation(requestWithVpToken("some.jwt"));
            Assert.fail("Expected CertifyException");
        } catch (CertifyException e) {
            Assert.assertEquals("invalid_request", e.getErrorCode());
        }
        verifyNoInteractions(vpSubmissionService);
    }
}
