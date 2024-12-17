package io.mosip.certify.core.exception;

public class RenderingTemplateException extends RuntimeException {
    private String errorCode;

    public RenderingTemplateException(String errorCode) {
        super(errorCode);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
