package io.mosip.certify.core.dto;

import jakarta.validation.constraints.*;
import lombok.Data;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Map;

/**
 * Request DTO for Pre-Authorized Code generation
 */
@Data
public class PreAuthorizedRequest {

    @NotBlank(message = "Credential configuration ID is required")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String credentialConfigurationId;

    @NotNull(message = "Claims are required")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Map<String, Object> claims;

    @Min(value = 60, message = "Minimum expiry is 60 seconds")
    @Max(value = 86400, message = "Maximum expiry is 24 hours")
    private Integer expiresIn;

    @Pattern(regexp = "^[0-9]{4,8}$", message = "Transaction code must be 4-8 digits")
    private String txCode;
}