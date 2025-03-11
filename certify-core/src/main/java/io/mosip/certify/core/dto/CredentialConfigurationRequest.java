package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CredentialConfigurationRequest {

    @NotEmpty(message = ErrorConstants.INVALID_REQUEST)
    private String vcTemplate;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private List<String> context;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private List<String> credentialType;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private String credentialFormat;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private String didUrl;

    @Valid
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private CredentialDisplay display;

    private List<String> order;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private String scope;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    @JsonProperty("cryptographic_binding_methods_supported")
    private List<String> cryptographicBindingMethodsSupported;

    @JsonProperty("credential_signing_alg_values_supported")
    private List<String> credentialSigningAlgValuesSupported;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    @JsonProperty("proof_types_supported")
    private Map<String, Object> proofTypesSupported;

    private List<Map<String, String>> pluginConfigurations;
}
