package io.mosip.certify.exception;

/**
 * Exception class for Bitstring Status List operations
 */
public class StatusListException extends Exception {

    private final String errorCode;

    public StatusListException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}