package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

/**
 * RFC 9457 / VCALM ProblemDetails error body for W3C VC API HTTP responses.
 * {@code type} MUST be a URL identifying the problem type.
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProblemDetails {

    /** URL identifying the problem type (REQUIRED). */
    private String type;

    /** Short human-readable summary (SHOULD). */
    private String title;

    /** Occurrence-specific explanation (SHOULD). */
    private String detail;

    /** HTTP status code for this occurrence. */
    private Integer status;

    /** URI identifying this occurrence of the problem. */
    private String instance;
}
