package io.mosip.certify.services;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.dto.authorizationrequest.AuthorizationRequestResponseDto;
import io.inji.verify.dto.authorizationrequest.VPRequestCreateDto;
import io.inji.verify.dto.authorizationrequest.VPRequestResponseDto;
import io.inji.verify.services.VerifiablePresentationRequestService;
import io.mosip.certify.core.dto.InteractiveAuthorizationRequest;
import io.mosip.certify.core.dto.VerifyVpResponse;
import io.mosip.certify.core.exception.CertifyException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.slf4j.LoggerFactory;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class IarVpRequestServiceTest {

    private static final String CONFIG_WITH_OVERRIDES =
            "{\"clientId\":\"hardcoded-client-id\",\"nonce\":\"hardcoded-nonce-value\"," +
            "\"dcqlQuery\":{\"credentials\":[{\"id\":\"c1\",\"format\":\"ldp_vc\"}]}}";

    private static final String CONFIG_WITHOUT_OVERRIDES =
            "{\"dcqlQuery\":{\"credentials\":[{\"id\":\"c1\",\"format\":\"ldp_vc\"}]}}";

    private static final String CONFIG_WITHOUT_DCQL = "{\"clientId\":\"anything\"}";

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private VerifiablePresentationRequestService vpRequestService;

    @InjectMocks
    private IarVpRequestService iarVpRequestService;

    @Before
    public void setup() {
        ReflectionTestUtils.setField(iarVpRequestService, "iaePostResponseMode", "iae_post");
        ReflectionTestUtils.setField(iarVpRequestService, "iaePostJwtResponseMode", "iae_post.jwt");
        ReflectionTestUtils.setField(iarVpRequestService, "certifyIaeEndpoint", "http://localhost:8090/v1/certify/oauth/iae");
        ReflectionTestUtils.setField(iarVpRequestService, "objectMapper", new ObjectMapper());
        ReflectionTestUtils.setField(iarVpRequestService, "vpRequestConfigUrl", "http://localhost/vp_request_config.json");
        ReflectionTestUtils.setField(iarVpRequestService, "verifierClientId", "verifier-client-id");
        ReflectionTestUtils.setField(iarVpRequestService, "activeProfile", "");
    }

    @Test
    public void should_mapDirectPostToIaePost_when_responseModeIsDirectPost() {
        VerifyVpResponse verifyResponse = buildVerifyVpResponse("direct_post");
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        Map<String, Object> result = (Map<String, Object>) iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);

        assertEquals("iae_post", result.get("response_mode"));
        assertEquals("vp_token", result.get("response_type"));
        assertEquals("test-client", result.get("client_id"));
    }

    @Test
    public void should_mapDirectPostJwtToIaePostJwt_when_responseModeIsDirectPostJwt() {
        VerifyVpResponse verifyResponse = buildVerifyVpResponse("direct_post.jwt");
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        Map<String, Object> result = (Map<String, Object>) iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);

        assertEquals("iae_post.jwt", result.get("response_mode"));
    }

    @Test
    public void should_passThroughResponseMode_when_modeIsUnknown() {
        VerifyVpResponse verifyResponse = buildVerifyVpResponse("some_other_mode");
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        Map<String, Object> result = (Map<String, Object>) iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);

        assertEquals("some_other_mode", result.get("response_mode"));
    }

    @Test(expected = CertifyException.class)
    public void should_throwCertifyException_when_responseModeIsEmpty() {
        VerifyVpResponse verifyResponse = buildVerifyVpResponse("");
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);
    }

    @Test(expected = CertifyException.class)
    public void should_throwCertifyException_when_authorizationDetailsAreNull() {
        VerifyVpResponse verifyResponse = new VerifyVpResponse();
        verifyResponse.setAuthorizationDetails(null);
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);
    }

    @Test
    public void should_embedDcqlQuery_when_convertingOpenId4VpRequest() {
        VerifyVpResponse verifyResponse = buildVerifyVpResponse("direct_post");
        InteractiveAuthorizationRequest iarRequest = buildIarRequest();

        Map<String, Object> result = (Map<String, Object>) iarVpRequestService.convertToOpenId4VpRequest(verifyResponse, iarRequest);

        assertNotNull(result.get("dcql_query"));
        Map<String, Object> dcqlQuery = (Map<String, Object>) result.get("dcql_query");
        assertNotNull(dcqlQuery.get("credentials"));

        List<Map<String, Object>> credentials = (List<Map<String, Object>>) dcqlQuery.get("credentials");
        assertEquals(1, credentials.size());
        assertEquals("mosip_verifiable_credential_id", credentials.get(0).get("id"));
        assertEquals("ldp_vc", credentials.get(0).get("format"));

        assertNull(result.get("presentation_definition"));

        assertEquals("http://localhost:8090/v1/certify/oauth/iae", result.get("response_uri"));
        assertEquals("test-nonce", result.get("nonce"));
    }

    private VerifyVpResponse buildVerifyVpResponse(String responseMode) {
        VerifyVpResponse response = new VerifyVpResponse();
        VerifyVpResponse.AuthorizationDetails authDetails = new VerifyVpResponse.AuthorizationDetails();
        authDetails.setResponseType("vp_token");
        authDetails.setResponseMode(responseMode);
        authDetails.setClientId("test-client");
        authDetails.setNonce("test-nonce");
        Map<String, Object> dcqlQuery = Map.of(
                "credentials", List.of(Map.of(
                        "id", "mosip_verifiable_credential_id",
                        "format", "ldp_vc"
                ))
        );
        authDetails.setDcqlQuery(dcqlQuery);
        response.setAuthorizationDetails(authDetails);
        return response;
    }

    private InteractiveAuthorizationRequest buildIarRequest() {
        InteractiveAuthorizationRequest request = new InteractiveAuthorizationRequest();
        request.setClientId("test-client");
        request.setResponseType("code");
        request.setCodeChallenge("test-challenge");
        request.setCodeChallengeMethod("S256");
        return request;
    }

    // -----------------------------------------------------------------------
    // createVpRequest — DCQL validation & clientId/nonce override branches
    // -----------------------------------------------------------------------

    private VPRequestResponseDto stubVpResponse() {
        VPRequestResponseDto dto = Mockito.mock(VPRequestResponseDto.class);
        AuthorizationRequestResponseDto auth = Mockito.mock(AuthorizationRequestResponseDto.class);
        when(dto.getTransactionId()).thenReturn("txn-1");
        when(dto.getRequestId()).thenReturn("req-1");
        when(dto.getAuthorizationDetails()).thenReturn(auth);
        when(auth.getResponseMode()).thenReturn("direct_post");
        return dto;
    }

    @Test
    public void createVpRequest_missingDcqlQuery_throwsUnknownError_beforeCallingLibrary() {
        when(restTemplate.getForObject(anyString(), eq(String.class)))
                .thenReturn(CONFIG_WITHOUT_DCQL);

        try {
            iarVpRequestService.createVpRequest(buildIarRequest());
            fail("Expected CertifyException(unknown_error)");
        } catch (CertifyException e) {
            assertEquals("unknown_error", e.getErrorCode());
            assertTrue(e.getMessage().toLowerCase().contains("dcqlquery"));
        }
        verifyNoInteractions(vpRequestService);
    }

    @Test
    public void createVpRequest_emptyConfigPayload_throwsUnknownError() {
        when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn("");

        try {
            iarVpRequestService.createVpRequest(buildIarRequest());
            fail("Expected CertifyException(unknown_error)");
        } catch (CertifyException e) {
            assertEquals("unknown_error", e.getErrorCode());
        }
        verifyNoInteractions(vpRequestService);
    }

    @Test
    public void createVpRequest_nonLocalProfile_withOverrides_ignoresOverrides_andWarns() {
        Logger serviceLogger = (Logger) LoggerFactory.getLogger(IarVpRequestService.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        serviceLogger.addAppender(appender);
        try {
            ReflectionTestUtils.setField(iarVpRequestService, "activeProfile", "prod");
            when(restTemplate.getForObject(anyString(), eq(String.class)))
                    .thenReturn(CONFIG_WITH_OVERRIDES);
            VPRequestResponseDto stub = stubVpResponse();
            when(vpRequestService.createAuthorizationRequest(any(VPRequestCreateDto.class), any())).thenReturn(stub);

            iarVpRequestService.createVpRequest(buildIarRequest());

            ArgumentCaptor<VPRequestCreateDto> captor = ArgumentCaptor.forClass(VPRequestCreateDto.class);
            verify(vpRequestService).createAuthorizationRequest(captor.capture(), eq(Optional.empty()));
            VPRequestCreateDto dto = captor.getValue();
            assertEquals("verifier-client-id", dto.getClientId());
            assertNull("nonce override must be ignored outside local profile", dto.getNonce());

            boolean warnEmitted = appender.list.stream()
                    .anyMatch(e -> e.getLevel() == Level.WARN
                            && e.getFormattedMessage().contains("Hardcoded values are ignored"));
            assertTrue("Expected WARN about ignored hardcoded clientId/nonce", warnEmitted);
        } finally {
            serviceLogger.detachAppender(appender);
        }
    }

    @Test
    public void createVpRequest_nonLocalProfile_noOverrides_usesVerifierClientIdAndNullNonce() {
        ReflectionTestUtils.setField(iarVpRequestService, "activeProfile", "prod");
        when(restTemplate.getForObject(anyString(), eq(String.class)))
                .thenReturn(CONFIG_WITHOUT_OVERRIDES);
        VPRequestResponseDto stub = stubVpResponse();
        when(vpRequestService.createAuthorizationRequest(any(VPRequestCreateDto.class), any())).thenReturn(stub);

        iarVpRequestService.createVpRequest(buildIarRequest());

        ArgumentCaptor<VPRequestCreateDto> captor = ArgumentCaptor.forClass(VPRequestCreateDto.class);
        verify(vpRequestService).createAuthorizationRequest(captor.capture(), eq(Optional.empty()));
        VPRequestCreateDto dto = captor.getValue();
        assertEquals("verifier-client-id", dto.getClientId());
        assertNull(dto.getNonce());
    }

    @Test
    public void createVpRequest_localProfile_withOverrides_appliesConfigClientIdAndNonce() {
        ReflectionTestUtils.setField(iarVpRequestService, "activeProfile", "local");
        ReflectionTestUtils.setField(iarVpRequestService,
                "vpRequestConfigUrl", "vp_request_config-local.json");
        VPRequestResponseDto stub = stubVpResponse();
        when(vpRequestService.createAuthorizationRequest(any(VPRequestCreateDto.class), any())).thenReturn(stub);

        iarVpRequestService.createVpRequest(buildIarRequest());

        ArgumentCaptor<VPRequestCreateDto> captor = ArgumentCaptor.forClass(VPRequestCreateDto.class);
        verify(vpRequestService).createAuthorizationRequest(captor.capture(), eq(Optional.empty()));
        VPRequestCreateDto dto = captor.getValue();
        assertEquals("injiverify.dev-int-inji.mosip.net/", dto.getClientId());
        assertEquals("NkdHJkBIbdOdQaAjWm8gpA", dto.getNonce());
        verifyNoInteractions(restTemplate);
    }

    @Test
    public void createVpRequest_localProfile_noOverrides_fallsBackToVerifierClientId() {
        ReflectionTestUtils.setField(iarVpRequestService, "activeProfile", "local");
        ReflectionTestUtils.setField(iarVpRequestService,
                "vpRequestConfigUrl", "vp_request_config.json"); // no clientId/nonce
        VPRequestResponseDto stub = stubVpResponse();
        when(vpRequestService.createAuthorizationRequest(any(VPRequestCreateDto.class), any())).thenReturn(stub);

        iarVpRequestService.createVpRequest(buildIarRequest());

        ArgumentCaptor<VPRequestCreateDto> captor = ArgumentCaptor.forClass(VPRequestCreateDto.class);
        verify(vpRequestService).createAuthorizationRequest(captor.capture(), eq(Optional.empty()));
        VPRequestCreateDto dto = captor.getValue();
        assertEquals("verifier-client-id", dto.getClientId());
        assertNull(dto.getNonce());
    }
}

