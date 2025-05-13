package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialIssuerMetadataDTO {

    @JsonProperty("credential_issuer")
    private String credentialIssuer;

    @JsonProperty("authorization_servers")
    private List<String> authorizationServers;

    @JsonProperty("credential_endpoint")
    private String credentialEndpoint;

    private List<Map<String, String>> display;

    @JsonIgnore
    public Map<String, CredentialConfigurationSupportedDTO> getCredentialConfigurationSupportedDTO() {
        throw new UnsupportedOperationException("This method must be overridden in child classes.");
    }
}
