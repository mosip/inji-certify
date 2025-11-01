package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class TokenRequest {
    @NotBlank(message = "Grant type is required")
    @JsonProperty("grant_type")
    private String grantType;

    @JsonProperty("pre-authorized_code")
    private String preAuthorizedCode;

    @JsonProperty("tx_code")
    private String txCode;

    // Optional: client_id (only when client authentication requires it)
    @JsonProperty("client_id")
    private String clientId;

    // Optional: code_verifier (for PKCE in hybrid flows, if used)
    @JsonProperty("code_verifier")
    private String codeVerifier;

    // Optional: redirect_uri (only in authorization_code flow)
    @JsonProperty("redirect_uri")
    private String redirectUri;

    // Optional: authorization_details (per RFC9396, for openid_credential)
    @JsonProperty("authorization_details")
    private String authorizationDetails;

    // Optional: resource (per RFC8707, recommended when multiple issuers)
    @JsonProperty("resource")
    private String resource;
}