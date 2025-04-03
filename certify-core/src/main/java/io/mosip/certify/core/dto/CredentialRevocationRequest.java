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
public class CredentialRevocationRequest {
    /**
     * REQUIRED. The ID of the credential to fetch.
     */
    @NotBlank(message = "Credential ID is required")
    private String credentialId;

    /**
     * REQUIRED. The reason for revocation (e.g., expired, compromised)
     */
    private String revocationReason;

    /**
     * REQUIRED. Cryptographic proof or hash representing the integrity of the revocation action (if needed)
     */
    @Valid
    @NotNull(message = ErrorConstants.INVALID_PROOF)
    private CredentialProof revocationProof;

}
