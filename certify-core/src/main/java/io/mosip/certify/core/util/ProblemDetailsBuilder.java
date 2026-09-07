package io.mosip.certify.core.util;

import io.mosip.certify.core.constants.ProblemDetailsTypes;
import io.mosip.certify.core.dto.ProblemDetails;
import org.springframework.http.HttpStatus;

/**
 * Shared builder for RFC 9457 / VCALM {@link ProblemDetails} bodies used by the
 * VC API filter and exception advice.
 */
public final class ProblemDetailsBuilder {

    private ProblemDetailsBuilder() {
    }

    public static ProblemDetails create(HttpStatus status, String type, String detail, String instance) {
        ProblemDetails body = new ProblemDetails();
        body.setType(type);
        body.setTitle(ProblemDetailsTypes.titleFor(type, status.getReasonPhrase()));
        body.setDetail(detail);
        body.setStatus(status.value());
        body.setInstance(instance);
        return body;
    }
}
