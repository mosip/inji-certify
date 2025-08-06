package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialConfigurationDTO {

    private String vcTemplate;

    private String credentialConfigKeyId;

    private List<String> contextURLs;

    private List<String> credentialTypes;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private String credentialFormat;

    private String didUrl;

    private String keyManagerAppId;

    private String keyManagerRefId;

    private String signatureAlgo; //Can be called as Proof algorithm

    private String signatureCryptoSuite;

    private String sdClaim;

    @Valid
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private List<MetaDataDisplayDTO> metaDataDisplay;

    private List<String> displayOrder;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private String scope;

    @JsonProperty("credentialSubjectDefinition")
    private Map<String, CredentialSubjectParametersDTO> credentialSubjectDefinition;

    @JsonProperty("msoMdocClaims")
    private Map<String, Map<String, ClaimsDisplayFieldsConfigDTO>> msoMdocClaims;

    @JsonProperty("sdJwtClaims")
    private Map<String, ClaimsDisplayFieldsConfigDTO> sdJwtClaims;

    @JsonProperty("doctype")
    private String docType;

    @JsonProperty("sdJwtVct")
    private String sdJwtVct;

    private List<Map<String, String>> pluginConfigurations;

    private List<String> credentialStatusPurposes;
}
