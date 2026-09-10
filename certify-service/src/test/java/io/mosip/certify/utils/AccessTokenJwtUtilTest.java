/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.IarSession;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class AccessTokenJwtUtilTest {

    @Mock
    private SignatureService signatureService;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private AccessTokenJwtUtil accessTokenJwtUtil;

    @Before
    public void setup() throws Exception {
        JWTSignatureResponseDto response = new JWTSignatureResponseDto();
        response.setJwtSignedData("signed.jwt.token");
        lenientSign(response);
    }

    private void lenientSign(JWTSignatureResponseDto response) throws Exception {
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"iss\":\"issuer\"}");
        when(signatureService.jwsSign(any(JWSSignatureRequestDto.class))).thenReturn(response);
    }

    private IarSession session(String identityData, String scope) {
        IarSession session = new IarSession();
        session.setIdentityData(identityData);
        session.setScope(scope);
        session.setClientId("client-123");
        session.setAuthSession("auth-1");
        session.setTransactionId("txn-1");
        return session;
    }

    @Test
    public void generateSignedJwt_fromRawParams_success() {
        String jwt = accessTokenJwtUtil.generateSignedJwt(
                "subject-data", "test_scope", "client-123",
                "https://issuer", "https://audience", 300);
        assertEquals("signed.jwt.token", jwt);
    }

    @Test
    public void generateSignedJwt_fromRawParams_nullClientId_success() {
        String jwt = accessTokenJwtUtil.generateSignedJwt(
                "subject-data", "test_scope", null,
                "https://issuer", "https://audience", 300);
        assertEquals("signed.jwt.token", jwt);
    }

    @Test
    public void generateSignedJwt_fromSession_success() {
        String jwt = accessTokenJwtUtil.generateSignedJwt(
                session("subject-data", "test_scope"), "https://issuer", "https://audience", 300);
        assertEquals("signed.jwt.token", jwt);
    }

    @Test
    public void generateSignedJwt_buildsRequestWithRs256AndCorrectAppId() {
        ArgumentCaptor<JWSSignatureRequestDto> captor = ArgumentCaptor.forClass(JWSSignatureRequestDto.class);

        accessTokenJwtUtil.generateSignedJwt(
                "subject-data", "test_scope", "client-123",
                "https://issuer", "https://audience", 300);

        org.mockito.Mockito.verify(signatureService).jwsSign(captor.capture());
        JWSSignatureRequestDto request = captor.getValue();
        assertEquals("RS256", request.getSignAlgorithm());
        assertEquals("CERTIFY_SERVICE", request.getApplicationId());
        assertEquals("", request.getReferenceId());
    }

    @Test
    public void generateSignedJwt_missingIdentityData_throws() {
        CertifyException ex = assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt("", "test_scope", "client-123",
                        "https://issuer", "https://audience", 300));
        assertEquals("invalid_request", ex.getErrorCode());
    }

    @Test
    public void generateSignedJwt_missingScope_throws() {
        assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt("subject-data", "", "client-123",
                        "https://issuer", "https://audience", 300));
    }

    @Test
    public void generateSignedJwt_fromSession_missingIdentityData_throws() {
        assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt(session(null, "test_scope"),
                        "https://issuer", "https://audience", 300));
    }

    @Test
    public void generateSignedJwt_fromSession_missingScope_throws() {
        assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt(session("subject-data", null),
                        "https://issuer", "https://audience", 300));
    }

    @Test
    public void generateSignedJwt_serializationFailure_wrappedAsUnknownError() throws Exception {
        when(objectMapper.writeValueAsString(any())).thenThrow(new JsonProcessingException("boom") {});
        CertifyException ex = assertThrows(CertifyException.class, () ->
                accessTokenJwtUtil.generateSignedJwt("subject-data", "test_scope", "client-123",
                        "https://issuer", "https://audience", 300));
        assertEquals("unknown_error", ex.getErrorCode());
    }
}
