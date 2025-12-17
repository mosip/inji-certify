package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.*;
import lombok.Data;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

/**
 * Request DTO for Pre-Authorized Code generation
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PreAuthorizedRequest {
    @NotBlank(message = "Credential configuration ID is required")
    @JsonProperty("credential_configuration_id")
    private String credentialConfigurationId;

    @NotNull(message = "Claims are required")
    @JsonProperty("claims")
    private Map<String, Object> claims;

    @Min(value = 60, message = "Minimum expiry is 60 seconds")
    @Max(value = 86400, message = "Maximum expiry is 24 hours")
    @JsonProperty("expires_in")
    private Integer expiresIn;

    @Pattern(regexp = "^[A-Za-z0-9]{4,8}$", message = "Transaction code must be 4-8 alphanumeric characters")
    @JsonProperty("tx_code")
    private String txCode;
}