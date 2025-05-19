package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Map;

@Data
@JsonInclude
public class CredentialIssuerMetadataVD12DTO extends CredentialIssuerMetadataDTO {
    @JsonProperty("credentials_supported")
    private Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedDTO;

    @Override
    public Map<String, CredentialConfigurationSupportedDTO> getCredentialConfigurationSupportedDTO() {
        return credentialConfigurationSupportedDTO;
    }

    public void setCredentialConfigurationSupportedDTO(Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedDTO) {
        this.credentialConfigurationSupportedDTO = credentialConfigurationSupportedDTO;
    }
}
