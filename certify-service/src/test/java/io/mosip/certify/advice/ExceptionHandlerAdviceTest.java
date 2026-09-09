package io.mosip.certify.advice;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import io.mosip.certify.dpop.DpopProofValidator;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

public class ExceptionHandlerAdviceTest {

    private final ExceptionHandlerAdvice advice = new ExceptionHandlerAdvice();
    private final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

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
}
