package io.mosip.certify.core.dto;

import lombok.Data;

/**
 * Optional W3C VC API issue options. Accepted only when omitted or empty for schema
 * compatibility. Non-blank proof hints are hard-rejected with {@code UNKNOWN_OPTION_PROVIDED}
 * (not silently ignored). Credential configuration id is supplied via
 * {@code X-Credential-Configuration-Id}, not here.
 */
@Data
public class VCApiIssueOptions {

    /** Rejected when non-blank; omit or leave empty. */
    private String type;

    /** Rejected when non-blank; omit or leave empty. */
    private String verificationMethod;

    /** Rejected when non-blank; omit or leave empty. */
    private String proofPurpose;

    /** Rejected when non-blank; omit or leave empty. */
    private String created;

    /** Rejected when non-blank; omit or leave empty. */
    private String challenge;

    /** Rejected when non-blank; omit or leave empty. */
    private String domain;
}
