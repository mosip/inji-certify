package io.mosip.certify.core.exception;

import io.mosip.certify.core.constants.ErrorConstants;

public class TemplateException extends RuntimeException {
    private String errorCode;

    public TemplateException() {
        super(ErrorConstants.UNKNOWN_ERROR);
        this.errorCode = ErrorConstants.UNKNOWN_ERROR;
    }

    public TemplateException(String errorCode) {
        super(errorCode);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
