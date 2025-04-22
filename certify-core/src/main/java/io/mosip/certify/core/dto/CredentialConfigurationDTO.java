package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.hibernate.annotations.Comment;

import java.util.List;
import java.util.Map;

@Data
public class CredentialConfigurationDTO {

    private String vcTemplate;

    private String credentialConfigKeyId;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private List<String> context;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private List<String> credentialType;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private String credentialFormat;

    private String didUrl;

    private String keyManagerAppId;

    private String keyManagerRefId;

    private String signatureAlgo; //Can be called as Proof algorithm

    private String sdClaim;

    @Valid
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private List<Map<String, Object>> display;

    private List<String> order;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private String scope;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    @JsonProperty("cryptographic_binding_methods_supported")
    private List<String> cryptographicBindingMethodsSupported;

    @NotNull
    @JsonProperty("credential_signing_alg_values_supported")
    private List<String> credentialSigningAlgValuesSupported;

    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    @JsonProperty("proof_types_supported")
    private Map<String, Object> proofTypesSupported;

    @JsonProperty("credentialSubject")
    private Map<String, Object> credentialSubject;

    @JsonProperty("claims")
    private Map<String, Object> claims;

    @JsonProperty("doctype")
    private String docType;

    private List<Map<String, String>> pluginConfigurations;
}
