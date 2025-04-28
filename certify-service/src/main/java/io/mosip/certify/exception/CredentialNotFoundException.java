package io.mosip.certify.exception;

/**
 * Exception thrown when a credential is not found in the system
 */
public class CredentialNotFoundException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Constructor with error message
     * 
     * @param message The error message
     */
    public CredentialNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructor with error message and cause
     * 
     * @param message The error message
     * @param cause The cause of the exception
     */
    public CredentialNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}