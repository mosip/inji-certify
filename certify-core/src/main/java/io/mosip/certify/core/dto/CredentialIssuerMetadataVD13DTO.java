package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialIssuerMetadataVD13DTO extends CredentialIssuerMetadataDTO {
    @JsonProperty("credential_configurations_supported")
    private Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedDTO;

    @Override
    public Map<String, CredentialConfigurationSupportedDTO> getCredentialConfigurationSupportedDTO() {
        return credentialConfigurationSupportedDTO;
    }

    public void setCredentialConfigurationSupportedDTO(Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedDTO) {
        this.credentialConfigurationSupportedDTO = credentialConfigurationSupportedDTO;
    }
}
