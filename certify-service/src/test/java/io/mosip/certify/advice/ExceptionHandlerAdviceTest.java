package io.mosip.certify.advice;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.OAuthTokenError;
import io.mosip.certify.core.dto.ResponseWrapper;
import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.exception.RenderingTemplateException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.context.request.ServletWebRequest;
import io.mosip.certify.dpop.DpopProofValidator;
import org.springframework.test.util.ReflectionTestUtils;

import javax.validation.ConstraintViolationException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class ExceptionHandlerAdviceTest {

    private ExceptionHandlerAdvice advice;
    private final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    private MessageSource messageSource;

    @Before
    public void setUp() {
        advice = new ExceptionHandlerAdvice();
        messageSource = Mockito.mock(MessageSource.class);
        when(messageSource.getMessage(anyString(), any(), anyString(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(2));
        ReflectionTestUtils.setField(advice, "messageSource", messageSource);
    }

    private ServletWebRequest webRequest(String uri) {
        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        when(req.getRequestURI()).thenReturn(uri);
        return new ServletWebRequest(req);
    }

    @Test
    public void should_returnInvalidRequest_when_unrecognizedPropertyIsProvided() {
        JsonParser parser = Mockito.mock(JsonParser.class);
        Mockito.when(parser.getCurrentLocation()).thenReturn(com.fasterxml.jackson.core.JsonLocation.NA);
        UnrecognizedPropertyException cause = UnrecognizedPropertyException.from(
                parser, Object.class, "unrecognized_field", null
        );
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", cause, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Unrecognized field 'unrecognized_field' in request", response.getBody().getError_description());
    }

    @Test
    public void should_returnInvalidRequest_when_fieldFormatIsInvalid() {
        InvalidFormatException cause = InvalidFormatException.from(
                null, "msg", "value", String.class
        );
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", cause, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Invalid format for field 'unknown' in request", response.getBody().getError_description());
    }

    @Test
    public void should_returnInvalidRequest_when_jsonSyntaxIsMalformed() {
        JsonParseException cause = new JsonParseException(null, "msg");
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", cause, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Malformed JSON syntax error", response.getBody().getError_description());
    }

    @Test
    public void should_returnInvalidRequest_when_requestStructureIsInvalid() {
        JsonMappingException cause = JsonMappingException.from(
                (JsonParser) null, "msg"
        );
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", cause, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Invalid request structure for field 'unknown'", response.getBody().getError_description());
    }

    @Test
    public void should_returnInvalidRequest_when_requestBodyIsUnreadable() {
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", (Throwable) null, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Invalid JSON request body", response.getBody().getError_description());
    }

    @Test
    public void should_escapeAuthParams_when_descriptionCarriesProofSuppliedText() {
        // DpopProofValidator names the rejected alg in its message, so description is
        // reachable from the DPoP proof's JOSE header. Unescaped, this closes the
        // quoted-string and appends an auth-param of the caller's choosing.
        String hostile = "Unsupported DPoP proof algorithm: x\", scope=\"openid";
        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        Mockito.when(req.getAttribute(Constants.AUTH_ERROR_ATTRIBUTE)).thenReturn(hostile);
        Mockito.when(req.getAttribute(Constants.AUTH_ERROR_CODE_ATTRIBUTE))
                .thenReturn(ErrorConstants.INVALID_DPOP_PROOF);
        Mockito.when(req.getAttribute(Constants.AUTH_SCHEME_ATTRIBUTE)).thenReturn("DPoP");
        // The advice asks the validator for the list, so stand one up here: @Value is not
        // processed for beans built with new, hence setting the field it binds.
        // A misconfigured property is the only way a quote reaches algs, but the header
        // must stay well-formed either way.
        DpopProofValidator validator = new DpopProofValidator();
        ReflectionTestUtils.setField(validator, "allowedAlgorithms", List.of("ES256", "RS\"256"));
        ReflectionTestUtils.setField(advice, "dpopProofValidator", validator);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(
                new NotAuthenticatedException(ErrorConstants.INVALID_DPOP_PROOF), req);

        Assert.assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        String challenge = response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
        Assert.assertNotNull(challenge);
        // every embedded quote is backslash-escaped, so the value stays one quoted-string
        Assert.assertTrue("the injected quotes must be escaped",
                challenge.contains("x\\\", scope=\\\"openid"));
        // and with the escaped quotes removed, no stray auth-param is left behind
        Assert.assertFalse("no unescaped auth-param may be injected",
                challenge.replace("\\\"", "").contains("scope=\""));
        // every quote in the header is a backslash-escaped one, algs included
        Assert.assertEquals("unescaped quotes remain in the challenge",
                0, challenge.replaceAll("\\\\\\\"", "").chars().filter(c -> c == '"').count()
                        - 6 /* the six delimiters of error, error_description and algs */);
    }

    // ---- folded from ExceptionHandlerAdviceExtraTest ----

    @Test
    public void should_routeToOAuthHandler_when_pathIsOAuth() {
        ResponseEntity<?> response = advice.handleExceptions(
                new IllegalArgumentException("bad"), webRequest("/v1/certify/oauth/token"));
        assertTrue(response.getBody() instanceof OAuthTokenError);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void should_routeToVciHandler_when_pathIsIssuance() {
        ResponseEntity<?> response = advice.handleExceptions(
                new CertifyException("some_error", "msg"), webRequest("/v1/certify/issuance/credential"));
        assertTrue(response.getBody() instanceof VCError);
    }

    @Test
    public void should_routeToInternalHandler_when_pathIsOther() {
        ResponseEntity<?> response = advice.handleExceptions(
                new RuntimeException("boom"), webRequest("/v1/certify/something-else"));
        assertTrue(response.getBody() instanceof ResponseWrapper);
    }

    @Test
    public void should_returnErrorWrapper_when_internalCertifyException() {
        ResponseEntity<?> response = advice.handleExceptions(
                new CertifyException("code1", "message1"), webRequest("/other"));
        ResponseWrapper wrapper = (ResponseWrapper) response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertFalse(wrapper.getErrors().isEmpty());
    }

    @Test
    public void should_returnNotFound_when_internalRenderingTemplateException() {
        ResponseEntity<?> response = advice.handleExceptions(
                new RenderingTemplateException("no_template"), webRequest("/other"));
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    public void should_returnNotFound_when_internalCredentialConfigException() {
        ResponseEntity<?> response = advice.handleExceptions(
                new CredentialConfigException("bad_config"), webRequest("/other"));
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    public void should_returnUnauthorized_when_internalAuthenticationCredentialsNotFound() {
        ResponseEntity<?> response = advice.handleExceptions(
                new AuthenticationCredentialsNotFoundException("nope"), webRequest("/other"));
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    public void should_returnForbidden_when_internalAccessDenied() {
        ResponseEntity<?> response = advice.handleExceptions(
                new AccessDeniedException("denied"), webRequest("/other"));
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }

    @Test
    public void should_returnErrorWrapper_when_internalMissingParam() {
        ResponseEntity<?> response = advice.handleExceptions(
                new MissingServletRequestParameterException("p", "String"), webRequest("/other"));
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    public void should_returnErrorWrapper_when_internalMediaTypeNotAcceptable() {
        ResponseEntity<?> response = advice.handleExceptions(
                new HttpMediaTypeNotAcceptableException("no"), webRequest("/other"));
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    public void should_returnErrorWrapper_when_internalConstraintViolation() {
        ConstraintViolationException ex = new ConstraintViolationException("invalid", Collections.emptySet());
        ResponseEntity<?> response = advice.handleExceptions(ex, webRequest("/other"));
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    public void should_returnErrorWrapper_when_internalUnknownError() {
        ResponseEntity<?> response = advice.handleExceptions(
                new RuntimeException("unexpected"), webRequest("/other"));
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    public void should_returnBadRequest_when_vciInvalidRequestException() {
        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(
                new InvalidRequestException("invalid_request"), Mockito.mock(HttpServletRequest.class));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_request", response.getBody().getError());
    }

    @Test
    public void should_returnBadRequest_when_vciCertifyException() {
        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(
                new CertifyException("vc_error", "vc failed"), Mockito.mock(HttpServletRequest.class));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("vc_error", response.getBody().getError());
    }

    @Test
    public void should_returnBadRequest_when_vciConstraintViolation() {
        ConstraintViolationException ex = new ConstraintViolationException("bad", Collections.emptySet());
        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(
                ex, Mockito.mock(HttpServletRequest.class));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void should_returnInternalServerError_when_vciUnknownError() {
        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(
                new RuntimeException("boom"), Mockito.mock(HttpServletRequest.class));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    public void should_returnServerErrorWithoutChallenge_when_tokenCouldNotBeJudgedForAConfigurationFault() {
        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        when(req.getAttribute(Constants.AUTH_ERROR_ATTRIBUTE)).thenReturn("server configuration error");
        when(req.getAttribute(Constants.AUTH_ERROR_CODE_ATTRIBUTE)).thenReturn(ErrorConstants.SERVER_ERROR);
        when(req.getAttribute(Constants.AUTH_SCHEME_ATTRIBUTE)).thenReturn("DPoP");

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(
                new NotAuthenticatedException(ErrorConstants.INVALID_AUTH_TOKEN), req);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorConstants.SERVER_ERROR, response.getBody().getError());
        // No challenge: there is nothing the caller could change about its credentials.
        Assert.assertNull(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE));
    }

    @Test
    public void should_answerBearerChallengeWithoutAlgs_when_dpopIsDisabledAndDpopSchemeIsRejected() {
        // What AccessTokenValidationFilter records for a DPoP-scheme request on a
        // deployment with DPoP disabled. The validator bean is absent in that mode.
        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        when(req.getAttribute(Constants.AUTH_ERROR_ATTRIBUTE)).thenReturn("DPoP is not supported by this deployment. Use a Bearer token.");
        when(req.getAttribute(Constants.AUTH_ERROR_CODE_ATTRIBUTE)).thenReturn(ErrorConstants.INVALID_AUTH_TOKEN);
        when(req.getAttribute(Constants.AUTH_SCHEME_ATTRIBUTE)).thenReturn(Constants.SCHEME_BEARER);
        ReflectionTestUtils.setField(advice, "dpopProofValidator", null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(new NotAuthenticatedException(), req);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(ErrorConstants.INVALID_AUTH_TOKEN, response.getBody().getError());
        assertEquals("DPoP is not supported by this deployment. Use a Bearer token.",
                response.getBody().getError_description());
        assertEquals("Bearer error=\"invalid_token\", error_description=\"DPoP is not supported by this deployment. Use a Bearer token.\"",
                response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE));
    }

    @Test
    public void should_notAdvertiseAlgs_when_dpopIsDisabledAndDpopBoundTokenIsPresentedAsBearer() {
        // The downgrade guard still answers invalid_dpop_proof, which normally carries algs.
        // With DPoP disabled no DPoP retry can succeed, so none may be advertised.
        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        when(req.getAttribute(Constants.AUTH_ERROR_ATTRIBUTE))
                .thenReturn("This access token is DPoP-bound and cannot be presented as a Bearer token.");
        when(req.getAttribute(Constants.AUTH_ERROR_CODE_ATTRIBUTE)).thenReturn(ErrorConstants.INVALID_DPOP_PROOF);
        when(req.getAttribute(Constants.AUTH_SCHEME_ATTRIBUTE)).thenReturn(Constants.SCHEME_BEARER);
        ReflectionTestUtils.setField(advice, "dpopProofValidator", null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(
                new NotAuthenticatedException(ErrorConstants.INVALID_DPOP_PROOF), req);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        String challenge = response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
        assertTrue(challenge.startsWith("Bearer "));
        assertFalse(challenge.contains("algs="));
    }

    @Test
    public void should_returnUnauthorizedWithChallenge_when_vciNotAuthenticated() {
        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        when(req.getAttribute(Constants.AUTH_ERROR_ATTRIBUTE)).thenReturn(null);
        when(req.getAttribute(Constants.AUTH_ERROR_CODE_ATTRIBUTE)).thenReturn(null);
        when(req.getAttribute(Constants.AUTH_SCHEME_ATTRIBUTE)).thenReturn(null);
        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(
                new NotAuthenticatedException("invalid_token"), req);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getHeaders().getFirst("WWW-Authenticate"));
    }

    @Test
    public void should_returnInvalidRequest_when_oauthIllegalArgument() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new IllegalArgumentException("bad param"));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_request", ((OAuthTokenError) response.getBody()).getError());
    }

    @Test
    public void should_returnBadRequest_when_oauthConstraintViolation() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new ConstraintViolationException("bad", Collections.emptySet()));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void should_returnBadRequest_when_oauthMissingParam() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new MissingServletRequestParameterException("grant_type", "String"));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void should_returnBadRequest_when_oauthMediaTypeNotAcceptable() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new HttpMediaTypeNotAcceptableException("no"));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void should_returnUnauthorized_when_oauthNotAuthenticated() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new NotAuthenticatedException("invalid_client"));
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("invalid_client", ((OAuthTokenError) response.getBody()).getError());
    }

    @Test
    public void should_returnForbidden_when_oauthAccessDenied() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new AccessDeniedException("denied"));
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertEquals("access_denied", ((OAuthTokenError) response.getBody()).getError());
    }

    @Test
    public void should_returnServerError_when_oauthUnknownError() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new RuntimeException("weird"));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("server_error", ((OAuthTokenError) response.getBody()).getError());
    }

    @Test
    public void should_mapInvalidGrant_when_oauthCertifyExceptionIsCodeExpired() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new CertifyException("authorization_code_expired", "expired"));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_grant", ((OAuthTokenError) response.getBody()).getError());
    }

    @Test
    public void should_mapInvalidClient_when_oauthCertifyExceptionIsClientMismatch() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new CertifyException("client_id_mismatch", "mismatch"));
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("invalid_client", ((OAuthTokenError) response.getBody()).getError());
    }

    @Test
    public void should_mapUnauthorizedClient_when_oauthCertifyExceptionIsUnauthorizedClient() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new CertifyException("unauthorized_client", "nope"));
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertEquals("unauthorized_client", ((OAuthTokenError) response.getBody()).getError());
    }

    @Test
    public void should_mapInvalidRequest_when_oauthCertifyExceptionIsOther() {
        ResponseEntity<Object> response = advice.handleOAuthControllerExceptions(
                new CertifyException("pkce_validation_failed", "pkce"));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_request", ((OAuthTokenError) response.getBody()).getError());
    }

    // --- unreadable bodies on the non-VCI endpoints (issue #878) ---------------------
    // These go through handleExceptions with a URI that is neither /oauth/ nor /issuance/,
    // which is how POST /v1/certify/credentials/status is routed. Before the shared
    // describeUnreadableBody() helper they all fell through to 200 + unknown_error and
    // returned Jackson's own message verbatim.

    /** The first error of a ResponseWrapper; the DTO declares errors as raw java.lang.Error. */
    private io.mosip.certify.core.dto.Error firstError(ResponseEntity<?> response) {
        ResponseWrapper wrapper = (ResponseWrapper) response.getBody();
        assertNotNull(wrapper);
        assertFalse(wrapper.getErrors().isEmpty());
        return (io.mosip.certify.core.dto.Error) wrapper.getErrors().get(0);
    }

    @Test
    public void should_returnInvalidRequest_when_internalBodyHasUnrecognizedField() {
        JsonParser parser = Mockito.mock(JsonParser.class);
        when(parser.getCurrentLocation()).thenReturn(com.fasterxml.jackson.core.JsonLocation.NA);
        UnrecognizedPropertyException cause = UnrecognizedPropertyException.from(
                parser, Object.class, "bogus_field", null);

        ResponseEntity<?> response = advice.handleExceptions(
                new HttpMessageNotReadableException("msg", cause, null), webRequest("/credentials/status"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_request", firstError(response).getErrorCode());
        assertEquals("Unrecognized field 'bogus_field' in request", firstError(response).getErrorMessage());
    }

    @Test
    public void should_returnInvalidRequest_when_internalBodyHasWrongFieldType() {
        // TC_InjiCertify_Update_Credential_Status_02 sends status="pass" for a Boolean field.
        InvalidFormatException cause = InvalidFormatException.from(null, "msg", "pass", Boolean.class);

        ResponseEntity<?> response = advice.handleExceptions(
                new HttpMessageNotReadableException("msg", cause, null), webRequest("/credentials/status"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_request", firstError(response).getErrorCode());
        assertEquals("Invalid format for field 'unknown' in request", firstError(response).getErrorMessage());
    }

    @Test
    public void should_returnInvalidRequest_when_internalBodyIsMalformedJson() {
        ResponseEntity<?> response = advice.handleExceptions(
                new HttpMessageNotReadableException("msg", new JsonParseException(null, "msg"), null),
                webRequest("/credentials/status"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_request", firstError(response).getErrorCode());
        assertEquals("Malformed JSON syntax error", firstError(response).getErrorMessage());
    }

    @Test
    public void should_returnInvalidRequest_when_internalBodyIsUnreadableWithoutCause() {
        ResponseEntity<?> response = advice.handleExceptions(
                new HttpMessageNotReadableException("msg", (Throwable) null, null),
                webRequest("/credentials/status"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_request", firstError(response).getErrorCode());
        assertEquals("Invalid JSON request body", firstError(response).getErrorMessage());
    }

    @Test
    public void should_notLeakJacksonMessage_when_internalBodyIsUnreadable() {
        // The reported symptom was the DTO class name reaching the caller. Guard it
        // explicitly: the response must carry neither the package name nor Jackson's prose.
        String jacksonProse = "JSON parse error: Unrecognized field \"c_nonce\" "
                + "(class io.mosip.certify.core.dto.CredentialRequest), not marked as ignorable";
        JsonParser parser = Mockito.mock(JsonParser.class);
        when(parser.getCurrentLocation()).thenReturn(com.fasterxml.jackson.core.JsonLocation.NA);
        UnrecognizedPropertyException cause = UnrecognizedPropertyException.from(
                parser, Object.class, "c_nonce", null);

        ResponseEntity<?> response = advice.handleExceptions(
                new HttpMessageNotReadableException(jacksonProse, cause, null),
                webRequest("/credentials/status"));

        String errorMessage = firstError(response).getErrorMessage();
        assertFalse(errorMessage.contains("io.mosip.certify"));
        assertFalse(errorMessage.contains("JSON parse error"));
        assertFalse("unknown_error must not be used for a body we could understand well enough to explain",
                "unknown_error".equals(firstError(response).getErrorCode()));
    }
}
