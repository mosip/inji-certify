package io.mosip.certify.core.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UpdateCredentialStatusRequest {
    private String credentialId;

    @NotNull
    @Valid
    private CredentialStatusDto credentialStatus;

    @NotNull
    private Boolean status;

    @Data
    public static class CredentialStatusDto {
        private String id;
        private String type;
        private String statusPurpose;
        @NotNull
        private Long statusListIndex;
        @NotNull
        private String statusListCredential;
    } 
}