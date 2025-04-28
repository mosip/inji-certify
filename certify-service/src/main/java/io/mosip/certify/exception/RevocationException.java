package io.mosip.certify.exception;

/**
 * Exception thrown when there's an error during credential revocation operations
 */
public class RevocationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructor with error message
     * 
     * @param message The error message
     */
    public RevocationException(String message) {
        super(message);
    }

    /**
     * Constructor with error message and cause
     * 
     * @param message The error message
     * @param cause The cause of the exception
     */
    public RevocationException(String message, Throwable cause) {
        super(message, cause);
    }
}