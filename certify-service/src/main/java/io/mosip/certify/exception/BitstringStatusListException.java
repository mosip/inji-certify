package io.mosip.certify.exception;

/**
 * Exception class for Bitstring Status List operations
 */
public class BitstringStatusListException extends Exception {

    private final String errorCode;

    public BitstringStatusListException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Gets the error URL as per W3C Problem Details format
     * As defined in section 3.5 of the specification
     */
    public String getErrorUrl() {
        return "https://www.w3.org/ns/credentials/status-list#" + errorCode;
    }
}