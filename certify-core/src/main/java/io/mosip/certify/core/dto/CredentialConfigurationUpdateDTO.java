package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialConfigurationUpdateDTO {

    private String vcTemplate;

    private String didUrl;

    private String keyManagerAppId;

    private String keyManagerRefId;

    private String signatureAlgo;

    private String signatureCryptoSuite;

    private String sdClaim;

    @Valid
    private List<MetaDataDisplayDTO> metaDataDisplay;

    private List<String> displayOrder;

    private String scope;

    @JsonProperty("credentialSubjectDefinition")
    private Map<String, CredentialSubjectParametersDTO> credentialSubjectDefinition;

    @JsonProperty("msoMdocClaims")
    private Map<String, Map<String, ClaimsDisplayFieldsConfigDTO>> msoMdocClaims;

    @JsonProperty("sdJwtClaims")
    private Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims;

    private List<Map<String, String>> pluginConfigurations;

    private List<String> credentialStatusPurposes;
}
