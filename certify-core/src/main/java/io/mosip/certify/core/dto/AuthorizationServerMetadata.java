package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Authorization Server Metadata as per RFC 8414
 * Source: https://www.rfc-editor.org/rfc/rfc8414.html
 * Used for discovery via /.well-known/oauth-authorization-server
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationServerMetadata {

    @JsonProperty("issuer")
    private String issuer;

    @JsonProperty("token_endpoint")
    private String tokenEndpoint;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("authorization_endpoint")
    private String authorizationEndpoint;

    @JsonProperty("response_types_supported")
    private List<String> responseTypesSupported;

    @JsonProperty("grant_types_supported")
    private List<String> grantTypesSupported;

    @JsonProperty("token_endpoint_auth_methods_supported")
    private List<String> tokenEndpointAuthMethodsSupported;

    @JsonProperty("code_challenge_methods_supported")
    private List<String> codeChallengeMethodsSupported;

    @JsonProperty("scopes_supported")
    private List<String> scopesSupported;
}