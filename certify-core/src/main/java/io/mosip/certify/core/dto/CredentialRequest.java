package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import jakarta.validation.Valid;
import lombok.Data;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

import java.util.Map;

@Data
public class CredentialRequest {

    @NotBlank(message = ErrorConstants.INVALID_CREDENTIAL_REQUEST)
    @JsonProperty("credential_configuration_id")
    private String credentialConfigId;

    /**
     * REQUIRED when the credential configuration requires holder binding; enforced by the issuance service.
     * JSON object containing proof(s) of possession of the key material the issued Credential shall be bound to.
     * Keys are proof types (e.g., "jwt"); values are non-empty lists of proof strings.
     */
    @Valid
    private Map<
            ProofType,
            List<
                    @NotBlank(message = VCIErrorConstants.INVALID_PROOF) String
                    >
            > proofs;
}