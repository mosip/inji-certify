package io.mosip.certify.core.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class CredentialConfigResponse {

    @NotEmpty
    private String id;

    @NotEmpty
    private String status;
}
