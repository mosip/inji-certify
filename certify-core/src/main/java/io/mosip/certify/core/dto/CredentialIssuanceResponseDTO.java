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
@Schema(description = "Model for credential issuance response")
public class CredentialIssuanceResponseDTO {

    @Schema(description = "Unique identifier for the credential")
    private String credentialId;

    @Schema(description = "Status of the credential")
    private String status;

    @Schema(description = "Date of issuance")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private LocalDateTime issueDate;

    @Schema(description = "Credential status property containing status metadata")
    private Map<String, Object> credentialStatus;
}