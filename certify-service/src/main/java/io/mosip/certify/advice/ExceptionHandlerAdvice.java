/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.advice;

import io.mosip.certify.core.dto.Error;
import io.mosip.certify.core.dto.ResponseWrapper;
import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.dto.OAuthTokenError;
import io.mosip.certify.core.exception.*;
import io.mosip.certify.core.util.CommonUtil;
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
        String pathInfo = ((ServletWebRequest)request).getRequest().getPathInfo();

        if(pathInfo != null && pathInfo.startsWith("/issuance/")) {
            return handleVCIControllerExceptions(ex);
        }

        if(pathInfo != null && pathInfo.startsWith("/oauth/")) {
            return handleOAuthControllerExceptions(ex);
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

    public ResponseEntity<VCError> handleVCIControllerExceptions(Exception ex) {
        if(ex instanceof MethodArgumentNotValidException) {
            FieldError fieldError = ((MethodArgumentNotValidException) ex).getBindingResult().getFieldError();
            String message = fieldError != null ? fieldError.getDefaultMessage() : ex.getMessage();
            return new ResponseEntity<VCError>(getVCErrorDto(message, message), HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof javax.validation.ConstraintViolationException) {
            Set<ConstraintViolation<?>> violations = ((ConstraintViolationException) ex).getConstraintViolations();
            String message = !violations.isEmpty() ? violations.stream().findFirst().get().getMessage() : ex.getMessage();
            return new ResponseEntity<VCError>(getVCErrorDto(message, message), HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof NotAuthenticatedException) {
            String errorCode = ((CertifyException) ex).getErrorCode();
            return new ResponseEntity<VCError>(getVCErrorDto(errorCode, getMessage(errorCode)), HttpStatus.UNAUTHORIZED);
        }
        if(ex instanceof InvalidRequestException) {
            String errorCode = ((InvalidRequestException) ex).getErrorCode();
            return new ResponseEntity<VCError>(getVCErrorDto(errorCode, getMessage(errorCode)), HttpStatus.BAD_REQUEST);
        }
        if(ex instanceof CertifyException) {
            String errorCode = ((CertifyException) ex).getErrorCode();
            String errorMessage = ex.getMessage();
            return new ResponseEntity<VCError>(getVCErrorDto(errorCode, errorMessage), HttpStatus.BAD_REQUEST);
        }
        log.error("Unhandled exception encountered in handler advice", ex);
        return new ResponseEntity<VCError>(getVCErrorDto(UNKNOWN_ERROR, ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
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
            OAuthTokenError oauthError = new OAuthTokenError("invalid_client", getMessage(errorCode));
            return new ResponseEntity<Object>(oauthError, HttpStatus.UNAUTHORIZED);
        }
        if(ex instanceof CertifyException) {
            String errorCode = ((CertifyException) ex).getErrorCode();
            // Map CertifyException error codes to OAuth 2.0 error codes
            String oauthErrorCode = mapToOAuthErrorCode(errorCode);
            OAuthTokenError oauthError = new OAuthTokenError(oauthErrorCode, getMessage(errorCode));
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

    private String getMessage(String errorCode) {
        try {
            messageSource.getMessage(errorCode, null, errorCode, Locale.getDefault());
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
}
