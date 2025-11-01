package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class AuthorizationDetail {

    @JsonProperty("type")
    private String type; // MUST be "openid_credential"

    @JsonProperty("credential_configuration_id")
    private String credentialConfigurationId;

    @JsonProperty("credential_identifiers")
    private List<String> credentialIdentifiers;
}