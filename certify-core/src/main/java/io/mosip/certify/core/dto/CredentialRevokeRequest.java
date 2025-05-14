package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class CredentialRevokeRequest {

    @NotBlank(message = ErrorConstants.INVALID_STATUS_LIST_CREDENTIAL_URL)
    private String statusListId;

    @NotNull(message = ErrorConstants.MISSING_STATUS_LIST_INDEX)
    private Long statusListIndex;

    @NotBlank(message = ErrorConstants.MISSING_STATUS_PURPOSE)
    private String statusPurpose;
}