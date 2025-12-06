package io.mosip.certify.core.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UpdateCredentialStatusRequest {
    @NotBlank
    private String credentialId;

    @NotNull
    private CredentialStatusDto credentialStatus;

    @NotNull
    private Boolean status;

    private String indexAllocator;

    @Data
    public static class CredentialStatusDto {
        private String id;
        private String type;
        private String statusPurpose;
        private Long statusListIndex;
        private String statusListCredential;
    } 
}