package io.mosip.certify.core.dto;

import java.time.LocalDateTime;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonFormat;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Model for credential issuance request")
public class CredentialIssuanceDTO {

    @Schema(description = "Unique identifier for the credential", required = true)
    private String credentialId;

    @Schema(description = "Identifier of the issuer", required = true)
    private String issuerId;

    @Schema(description = "Information about the credential holder", required = true)
    private Map<String, Object> holderInfo;

    @Schema(description = "Type of the credential", required = true)
    private String credentialType;

    @Schema(description = "Date of issuance", required = true)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private LocalDateTime issueDate;

    @Schema(description = "Date of expiration", required = false)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private LocalDateTime expirationDate;

    @Schema(description = "Status purpose for the credential", required = true)
    private String statusPurpose;

    @Schema(description = "Additional credential data", required = false)
    private Map<String, Object> credentialData;

    @Schema(description = "Username of the person initiating the issuance", required = true)
    private String userName;
}