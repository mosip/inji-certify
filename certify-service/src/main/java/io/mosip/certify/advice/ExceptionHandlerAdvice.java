/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.advice;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.Error;
import io.mosip.certify.core.dto.ResponseWrapper;
import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.dto.OAuthTokenError;
import io.mosip.certify.core.exception.*;
import io.mosip.certify.core.util.CommonUtil;
import io.mosip.certify.dpop.DpopProofValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.TypeMismatchException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.io.IOException;
import java.util.*;

import static io.mosip.certify.core.constants.ErrorConstants.*;
import static io.mosip.certify.core.constants.VCIErrorConstants.INVALID_REQUEST;

@Slf4j
@ControllerAdvice
public class ExceptionHandlerAdvice extends ResponseEntityExceptionHandler implements AccessDeniedHandler {

    @Autowired
    MessageSource messageSource;

    /**
     * Source of the {@code algs} parameter advertised in a DPoP challenge (RFC 9449
     * §5.1), so a client that guessed wrong is told what this issuer will accept.
     *
     * <p>The validator is asked for the list rather than the property being bound here a
     * second time: two bindings of one key can be edited apart, and a challenge that
     * advertises algorithms the validator does not accept sends a wallet developer
     * chasing a fault that is not theirs. Optional so an advice built outside a Spring
     * context still answers, just without the {@code algs} hint.
     */
    @Autowired(required = false)
    private DpopProofValidator dpopProofValidator;

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex, HttpHeaders headers,
                                                                  HttpStatusCode status, WebRequest request) {
        return handleExceptions(ex, request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotAcceptable(
            HttpMediaTypeNotAcceptableException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        return handleExceptions(ex, request);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(
            MissingServletRequestParameterException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {
        return handleExceptions(ex, request);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {
        return handleExceptions(ex, request);
    }

    protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException ex, HttpHeaders headers,
                                                        HttpStatus status, WebRequest request) {
        return handleExceptions(ex, request);
    }

    @ExceptionHandler(value = { Exception.class, RuntimeException.class, MissingRequestHeaderException.class })
    public ResponseEntity handleExceptions(Exception ex, WebRequest request) {
        log.error("Unhandled exception encountered in handler advice", ex);
        HttpServletRequest servletRequest = ((ServletWebRequest) request).getRequest();
        String path = servletRequest.getRequestURI();
        if (path != null && path.contains("/oauth/")) {
            return handleOAuthControllerExceptions(ex);
        }
        if (path != null && path.contains("/issuance/")) {
            return handleVCIControllerExceptions(ex, servletRequest);
        }

        return handleInternalControllerException(ex);
    }


    private ResponseEntity<ResponseWrapper> handleInternalControllerException(Exception ex) {
        if(ex instanceof MethodArgumentNotValidException) {
            List<Error> errors = new ArrayList<>();
            for (FieldError error : ((MethodArgumentNotValidException) ex).getBindingResult().getFieldErrors()) {
                errors.add(new Error(error.getDefaultMessage(), error.getField() + ": " + error.getDefaultMessage()));
            }
            return new ResponseEntity<ResponseWrapper>(getResponseWrapper(errors), HttpStatus.OK);
        }
        if(ex instanceof javax.validation.ConstraintViolationException) {
            List<Error> errors = new ArrayList<>();
            Set<javax.validation.ConstraintViolation<?>> violations = ((javax.validation.ConstraintViolationException) ex).getConstraintViolations();
            for(javax.validation.ConstraintViolation<?> cv : violations) {
                errors.add(new Error(INVALID_REQUEST,cv.getPropertyPath().toString() + ": " + cv.getMessage()));
            }
            return new ResponseEntity<ResponseWrapper>(getResponseWrapper(errors), HttpStatus.OK);
        }
        if(ex instanceof MissingServletRequestParameterException) {
            return new ResponseEntity<ResponseWrapper>(getResponseWrapper(INVALID_REQUEST, ex.getMessage()),
                    HttpStatus.OK);
        }
        if(ex instanceof HttpMediaTypeNotAcceptableException) {
            return new ResponseEntity<ResponseWrapper>(getResponseWrapper(INVALID_REQUEST, ex.getMessage()),
                    HttpStatus.OK);
        }
        if(ex instanceof CertifyException) {
            String errorCode = ((CertifyException) ex).getErrorCode();
            String errorMessage = ex.getMessage();
            return new ResponseEntity<ResponseWrapper>(getResponseWrapper(errorCode, errorMessage), HttpStatus.OK);
        }
        if(ex instanceof RenderingTemplateException) {
            return new ResponseEntity<>(getResponseWrapper(INVALID_REQUEST, ex.getMessage()) ,HttpStatus.NOT_FOUND);
        }
        if(ex instanceof CredentialConfigException) {
            return new ResponseEntity<>(getResponseWrapper(INVALID_REQUEST, ex.getMessage()) ,HttpStatus.NOT_FOUND);
        }
        if(ex instanceof AuthenticationCredentialsNotFoundException) {
            return new ResponseEntity<ResponseWrapper>(getResponseWrapper(HttpStatus.UNAUTHORIZED.name(),
                    HttpStatus.UNAUTHORIZED.getReasonPhrase()), HttpStatus.UNAUTHORIZED);
        }
        if(ex instanceof AccessDeniedException) {
            return new ResponseEntity<ResponseWrapper>(getResponseWrapper(HttpStatus.FORBIDDEN.name(),
                    HttpStatus.FORBIDDEN.getReasonPhrase()), HttpStatus.FORBIDDEN);
        }
        return new ResponseEntity<ResponseWrapper>(getResponseWrapper(UNKNOWN_ERROR, ex.getMessage()), HttpStatus.OK);
    }

    public ResponseEntity<VCError> handleVCIControllerExceptions(Exception ex, HttpServletRequest request) {
        if(ex instanceof HttpMessageNotReadableException) {
            String message = "Invalid JSON request body";
            Throwable cause = ex.getCause();

            // Provide more specific error based on the root cause
            if (cause instanceof UnrecognizedPropertyException) {
                UnrecognizedPropertyException propEx =
                    (UnrecognizedPropertyException) cause;
                message = String.format("Unrecognized field '%s' in request", propEx.getPropertyName());
            } else if (cause instanceof InvalidFormatException) {
                InvalidFormatException formatEx = (InvalidFormatException) cause;
                String fieldName = formatEx.getPath().isEmpty() ? "unknown"
                    : formatEx.getPath().get(formatEx.getPath().size() - 1).getFieldName();
                message = String.format("Invalid format for field '%s' in request", fieldName);
            } else if (cause instanceof JsonParseException) {
                message = "Malformed JSON syntax error";
            } else if (cause instanceof JsonMappingException) {
                JsonMappingException mappingEx = (JsonMappingException) cause;
                String fieldName = mappingEx.getPath().isEmpty() ? "unknown"
                    : mappingEx.getPath().get(mappingEx.getPath().size() - 1).getFieldName();
                message = String.format("Invalid request structure for field '%s'", fieldName);
            }

            return new ResponseEntity<>(getVCErrorDto(INVALID_REQUEST, message), HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof MethodArgumentNotValidException) {
            FieldError fieldError = ((MethodArgumentNotValidException) ex).getBindingResult().getFieldError();
            String message = fieldError != null ? fieldError.getDefaultMessage() : ex.getMessage();
            return new ResponseEntity<>(getVCErrorDto(message, message), HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof javax.validation.ConstraintViolationException) {
            Set<ConstraintViolation<?>> violations = ((ConstraintViolationException) ex).getConstraintViolations();
            String message = !violations.isEmpty() ? violations.stream().findFirst().get().getMessage() : ex.getMessage();
            return new ResponseEntity<>(getVCErrorDto(message, message), HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof NotAuthenticatedException) {
            Object reason = request.getAttribute(Constants.AUTH_ERROR_ATTRIBUTE);
            // The filter cannot propagate its own exception - it records the failure and
            // lets the chain run on - so both the code and the description are read back
            // from the request. Without the code, every DPoP failure would surface as the
            // generic invalid_token carried by NotAuthenticatedException.
            Object code = request.getAttribute(Constants.AUTH_ERROR_CODE_ATTRIBUTE);
            String errorCode = (code instanceof String) ? (String) code : ((CertifyException) ex).getErrorCode();
            String description = (reason instanceof String) ? (String) reason : getMessage(errorCode, errorCode);
            HttpHeaders headers = new HttpHeaders();
            // RFC 9449 §7.1: challenge in the scheme the caller used, so a DPoP client is
            // not told to retry with Bearer - which it must not do for a bound token. The
            // algs parameter advertises what the proof may be signed with, as eSignet does.
            Object schemeAttribute = request.getAttribute(Constants.AUTH_SCHEME_ATTRIBUTE);
            String scheme = (schemeAttribute instanceof String) ? (String) schemeAttribute : Constants.SCHEME_BEARER;
            // description can carry proof-supplied text - DpopProofValidator names the
            // rejected alg, for instance - so it is escaped before going into the header.
            // Unescaped, a proof with alg = x", scope="openid would inject an auth-param.
            StringBuilder challenge = new StringBuilder(scheme)
                    .append(" error=\"").append(quoteAuthParam(errorCode)).append('"')
                    .append(", error_description=\"").append(quoteAuthParam(description)).append('"');
            // algs comes from configuration rather than the request, so it is not
            // attacker-controlled - but it is still a dynamic value, and escaping it
            // keeps every quoted auth-param in this header safe by the same rule.
            List<String> algs = dpopProofValidator == null
                    ? List.of()
                    : dpopProofValidator.getAllowedAlgorithms();
            if(INVALID_DPOP_PROOF.equals(errorCode) && !algs.isEmpty()) {
                challenge.append(", algs=\"")
                        .append(quoteAuthParam(String.join(" ", algs)))
                        .append('"');
            }
            headers.set(HttpHeaders.WWW_AUTHENTICATE, challenge.toString());
            return new ResponseEntity<>(getVCErrorDto(errorCode, description), headers, HttpStatus.UNAUTHORIZED);
        }
        if(ex instanceof InvalidRequestException) {
            String errorCode = ((InvalidRequestException) ex).getErrorCode();
            return new ResponseEntity<>(getVCErrorDto(errorCode, getMessage(errorCode, errorCode)), HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof CertifyException) {
            String errorCode = ((CertifyException) ex).getErrorCode();
            String errorMessage = ex.getMessage();
            return new ResponseEntity<>(getVCErrorDto(errorCode, errorMessage), HttpStatus.BAD_REQUEST);
        }
        log.error("Unhandled exception encountered in handler advice", ex);
        return new ResponseEntity<>(getVCErrorDto(UNKNOWN_ERROR, ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    public ResponseEntity<Object> handleOAuthControllerExceptions(Exception ex) {
        if(ex instanceof IllegalArgumentException) {
            OAuthTokenError oauthError = new OAuthTokenError("invalid_request", ex.getMessage());
            return new ResponseEntity<Object>(oauthError, HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof MethodArgumentNotValidException) {
            FieldError fieldError = ((MethodArgumentNotValidException) ex).getBindingResult().getFieldError();
            String message = fieldError != null ? fieldError.getDefaultMessage() : ex.getMessage();
            OAuthTokenError oauthError = new OAuthTokenError("invalid_request", message);
            return new ResponseEntity<Object>(oauthError, HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof javax.validation.ConstraintViolationException) {
            Set<ConstraintViolation<?>> violations = ((ConstraintViolationException) ex).getConstraintViolations();
            String message = !violations.isEmpty() ? violations.stream().findFirst().get().getMessage() : ex.getMessage();
            OAuthTokenError oauthError = new OAuthTokenError("invalid_request", message);
            return new ResponseEntity<Object>(oauthError, HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof MissingServletRequestParameterException) {
            OAuthTokenError oauthError = new OAuthTokenError("invalid_request", ex.getMessage());
            return new ResponseEntity<Object>(oauthError, HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof HttpMediaTypeNotAcceptableException) {
            OAuthTokenError oauthError = new OAuthTokenError("invalid_request", ex.getMessage());
            return new ResponseEntity<Object>(oauthError, HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof NotAuthenticatedException) {
            String errorCode = ((CertifyException) ex).getErrorCode();
            OAuthTokenError oauthError = new OAuthTokenError("invalid_client", getMessage(errorCode, errorCode));
            return new ResponseEntity<Object>(oauthError, HttpStatus.UNAUTHORIZED);
        }
        if(ex instanceof CertifyException) {
            String errorCode = ((CertifyException) ex).getErrorCode();
            String errorMessage = ex.getMessage();
            // Map CertifyException error codes to OAuth 2.0 error codes
            String oauthErrorCode = mapToOAuthErrorCode(errorCode);
            OAuthTokenError oauthError = new OAuthTokenError(oauthErrorCode, getMessage(errorCode, errorMessage));
            HttpStatus status = getOAuthErrorStatus(oauthErrorCode);
            return new ResponseEntity<Object>(oauthError, status);
        }
        if(ex instanceof AccessDeniedException) {
            OAuthTokenError oauthError = new OAuthTokenError("access_denied", "Access denied");
            return new ResponseEntity<Object>(oauthError, HttpStatus.FORBIDDEN);
        }
        log.error("Unhandled exception encountered in OAuth controller", ex);
        OAuthTokenError oauthError = new OAuthTokenError("server_error", "Internal server error");
        return new ResponseEntity<Object>(oauthError, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private ResponseWrapper getResponseWrapper(String errorCode, String errorMessage) {
        Error error = new Error();
        error.setErrorCode(errorCode);
        error.setErrorMessage(errorMessage);
        return getResponseWrapper(Arrays.asList(error));
    }

    private ResponseWrapper getResponseWrapper(List<Error> errors) {
        ResponseWrapper responseWrapper = new ResponseWrapper<>();
        responseWrapper.setResponseTime(CommonUtil.getUTCDateTime());
        responseWrapper.setErrors(errors);
        return responseWrapper;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        handleExceptions(accessDeniedException, (WebRequest) request);
    }

    private String getMessage(String errorCode, String defaultMessage) {
        try {
            return messageSource.getMessage(errorCode, null, defaultMessage, Locale.getDefault());
        } catch (NoSuchMessageException ex) {
            log.error("Message not found in the i18n bundle", ex);
        }
        return errorCode;
    }

    private VCError getVCErrorDto(String errorCode, String description) {
        VCError errorRespDto = new VCError();
        errorRespDto.setError(errorCode);
        errorRespDto.setError_description(description);
        return errorRespDto;
    }

    private String mapToOAuthErrorCode(String certifyErrorCode) {
        if (certifyErrorCode == null) {
            return "server_error";
        }

        switch (certifyErrorCode.toLowerCase()) {
            case "invalid_request":
            case "invalid_grant":
            case "invalid_client":
            case "unauthorized_client":
            case "unsupported_grant_type":
            case "invalid_scope":
                return certifyErrorCode.toLowerCase();
            case "invalid_auth_session":
            case "session_not_found":
            case "invalid_authorization_code":
            case "authorization_code_not_found":
            case "authorization_code_expired":
            case "authorization_code_already_used":
                return "invalid_grant";
            case "client_id_mismatch":
                return "invalid_client";
            case "interaction_required":
                return "interaction_required";
            case "invalid_redirect_uri":
            case "pkce_validation_failed":
            case "invalid_code_verifier":
            default:
                return "invalid_request";
        }
    }

    private HttpStatus getOAuthErrorStatus(String oauthErrorCode) {
        if (oauthErrorCode == null) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }

        switch (oauthErrorCode.toLowerCase()) {
            case "invalid_client":
                return HttpStatus.UNAUTHORIZED;
            case "invalid_grant":
            case "invalid_request":
            case "unsupported_grant_type":
            case "invalid_scope":
            case "interaction_required":
                return HttpStatus.BAD_REQUEST;
            case "unauthorized_client":
                return HttpStatus.FORBIDDEN;
            case "server_error":
                return HttpStatus.INTERNAL_SERVER_ERROR;
            default:
                return HttpStatus.BAD_REQUEST;
        }
    }

    /**
     * Escapes a value for an RFC 9110 quoted-string auth-param.
     *
     * <p>Backslash and double quote are backslash-escaped so they cannot close the
     * quoted-string and start another parameter; control characters, which would let a
     * value break the header itself, are replaced with a space.
     */
    private static String quoteAuthParam(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            if (c < 0x20 || c == 0x7f) {
                out.append(' ');
            } else if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
