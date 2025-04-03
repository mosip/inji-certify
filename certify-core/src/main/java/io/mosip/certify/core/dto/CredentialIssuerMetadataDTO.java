package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CredentialIssuerMetadataDTO {

    @JsonProperty("credential_issuer")
    private String credentialIssuer;

    @JsonProperty("authorization_servers")
    private List<String> authorizationServers;

    @JsonProperty("credential_endpoint")
    private String credentialEndpoint;

    private List<Map<String, String>> display;

    @JsonProperty("credential_configurations_supported")
    private Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedDTO;
}
