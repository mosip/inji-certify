package io.mosip.certify.exception;

public class CredentialIssuanceException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public CredentialIssuanceException(String message) {
        super(message);
    }

    public CredentialIssuanceException(String message, Throwable cause) {
        super(message, cause);
    }
}