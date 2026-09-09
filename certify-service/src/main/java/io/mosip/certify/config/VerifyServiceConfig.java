package io.mosip.certify.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.inji.verify.dto.dcql.DCQLQueryDto;
import lombok.Data;

/**
 * Configuration class for VP request configuration (vp_request_config.json).
 * Contains the DCQL query definition and optional override fields for local testing.
 *
 * <p>The {@code clientId} and {@code nonce} fields are honored ONLY when the {@code local}
 * Spring profile is active. They exist to make local end-to-end testing deterministic
 * against a hardcoded sample VP token (see {@code vp_request_config-local.json}). On any
 * other profile these fields are ignored and a WARN is logged, so the embedded verify
 * library generates its own nonce and VP replay protection is preserved.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class VerifyServiceConfig {
    @JsonProperty("dcqlQuery")
    private DCQLQueryDto dcqlQuery;

    @JsonProperty("clientId")
    private String clientId;

    @JsonProperty("nonce")
    private String nonce;
}

