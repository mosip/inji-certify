package io.mosip.certify.core.exception;

public class CredentialConfigException extends RuntimeException {
    private String errorCode;

    public CredentialConfigException(String errorCode) {
        super(errorCode);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
