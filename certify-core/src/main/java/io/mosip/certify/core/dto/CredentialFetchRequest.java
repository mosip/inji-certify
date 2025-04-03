package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Request DTO for fetching credential status information
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CredentialFetchRequest {
    /**
     * REQUIRED. The ID of the credential to fetch.
     */
    @NotBlank(message = "Credential ID is required")
    private String credentialId;

    /**
     * REQUIRED. The ID of the issuer.
     */
    @NotBlank(message = "Issuer ID is required")
    private String issuerId;

    /**
     * OPTIONAL. The ID of the holder.
     */
    private String holderId;

}
