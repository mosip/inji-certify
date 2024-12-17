package io.mosip.certify.core.exception;

import io.mosip.certify.core.constants.ErrorConstants;

public class RenderingTemplateException extends RuntimeException {
    private String errorCode;

    public RenderingTemplateException() {
        super(ErrorConstants.UNKNOWN_ERROR);
        this.errorCode = ErrorConstants.UNKNOWN_ERROR;
    }

    public RenderingTemplateException(String errorCode) {
        super(errorCode);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
