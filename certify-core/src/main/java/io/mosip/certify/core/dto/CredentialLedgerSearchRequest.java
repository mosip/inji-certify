package io.mosip.certify.core.dto;

import java.util.Map;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;

@Data
public class CredentialLedgerSearchRequest {
    private String credentialId;

    @NotBlank(message = "issuerId is mandatory")
    private String issuerId;

    @NotBlank(message = "credentialType is mandatory")
    private String credentialType;

    private Map<String, String> indexedAttributesEquals;
}