package io.mosip.certify.core.dto;


import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;

@Data
public class CredentialDefinition {

    @JsonProperty("@context")
    private List<@NotBlank(message = ErrorConstants.INVALID_REQUEST) String> context;

    @NotEmpty(message = ErrorConstants.INVALID_REQUEST)
    private List<@NotBlank(message = ErrorConstants.INVALID_REQUEST) String> type;

    private Map<String, Object> credentialSubject;

}
