package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialConfigurationSupportedDTO {

    private String format;

    @JsonProperty("doctype")
    private String docType;

    private String scope;

    private String id;

    @JsonProperty("cryptographic_binding_methods_supported")
    private List<String> cryptographicBindingMethodsSupported;

    @JsonProperty("cryptographic_suites_supported")
    private List<String> cryptographicSuitesSupported;

    @JsonProperty("credential_signing_alg_values_supported")
    private List<String> credentialSigningAlgValuesSupported;

    @JsonProperty("proof_types_supported")
    private Map<String, Object> proofTypesSupported;

    @JsonProperty("credential_definition")
    private CredentialDefinition credentialDefinition;

    private Map<String, Object> claims;

    private List<MetaDataDisplayDTO> display;

    private List<String> order;

    private String vct;
}
