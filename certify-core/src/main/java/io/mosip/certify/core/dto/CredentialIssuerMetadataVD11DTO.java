package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Data
@JsonInclude
public class CredentialIssuerMetadataVD11DTO extends CredentialIssuerMetadataDTO {
    @JsonProperty("credentials_supported")
    private List<CredentialConfigurationSupportedDTO> credentialConfigurationSupportedDTO;

    @Override
    public Map<String, CredentialConfigurationSupportedDTO> getCredentialConfigurationSupportedDTO() {
        return credentialConfigurationSupportedDTO.stream()
                .collect(Collectors.toMap(CredentialConfigurationSupportedDTO::getId, dto -> dto));
    }

    public void setCredentialConfigurationSupportedDTO(List<CredentialConfigurationSupportedDTO> credentialConfigurationSupportedDTO) {
        this.credentialConfigurationSupportedDTO = credentialConfigurationSupportedDTO;
    }
}
