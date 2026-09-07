package io.mosip.certify.core.constants;

/**
 * Problem type URLs for VCALM / RFC 9457 error responses.
 * <p>
 * VCDM 2.0 types apply when processing the credential document.
 * VCALM defines {@link #UNKNOWN_OPTION_PROVIDED} for unknown API options.
 * HTTP-layer failures with no W3C issuance type use {@link #ABOUT_BLANK}.
 */
public final class ProblemDetailsTypes {

    private ProblemDetailsTypes() {
    }

    public static final String ABOUT_BLANK = "about:blank";

    /** An option unknown to this implementation was provided. */
    public static final String UNKNOWN_OPTION_PROVIDED =
            "https://www.w3.org/TR/vcalm#UNKNOWN_OPTION_PROVIDED";

    /** Input could not be parsed as JSON / a credential document. */
    public static final String PARSING_ERROR =
            "https://www.w3.org/TR/vc-data-model-2.0#PARSING_ERROR";

    /** A property value is malformed or does not match the expected document shape. */
    public static final String MALFORMED_VALUE_ERROR =
            "https://www.w3.org/TR/vc-data-model-2.0#MALFORMED_VALUE_ERROR";

    /** A value is outside the expected range (for example validUntil not after validFrom). */
    public static final String RANGE_ERROR =
            "https://www.w3.org/TR/vc-data-model-2.0#RANGE_ERROR";

    public static String titleFor(String type, String httpReasonPhrase) {
        if (PARSING_ERROR.equals(type)) {
            return "Parsing Error";
        }
        if (MALFORMED_VALUE_ERROR.equals(type)) {
            return "Malformed Value Error";
        }
        if (RANGE_ERROR.equals(type)) {
            return "Range Error";
        }
        if (UNKNOWN_OPTION_PROVIDED.equals(type)) {
            return "Unknown Option Provided";
        }
        return httpReasonPhrase;
    }
}
