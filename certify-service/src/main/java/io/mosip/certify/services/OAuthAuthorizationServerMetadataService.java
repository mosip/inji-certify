/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.dto.OAuthAuthorizationServerMetadataDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

/**
 * Service for handling OAuth 2.0 Authorization Server Metadata
 */
@Slf4j
@Service
public class OAuthAuthorizationServerMetadataService {

    @Value("${mosip.certify.oauth.issuer}")
    private String issuer;

    @Value("${mosip.certify.oauth.token-endpoint}")
    private String tokenEndpoint;

    @Value("${mosip.certify.oauth.grant-types-supported}")
    private String grantTypesSupported;

    @Value("${mosip.certify.oauth.response-types-supported}")
    private String responseTypesSupported;

    @Value("${mosip.certify.oauth.code-challenge-methods-supported}")
    private String codeChallengeMethodsSupported;

    @Value("${mosip.certify.oauth.interactive-authorization-endpoint}")
    private String interactiveAuthorizationEndpoint;

    /**
     * Builds and returns OAuth 2.0 Authorization Server Metadata
     * @return OAuthAuthorizationServerMetadataDTO containing the OAuth Authorization Server metadata
     */
    public OAuthAuthorizationServerMetadataDTO getOAuthAuthorizationServerMetadata() {
        log.debug("Building OAuth Authorization Server metadata");

        OAuthAuthorizationServerMetadataDTO metadata = new OAuthAuthorizationServerMetadataDTO();
        
        metadata.setIssuer(issuer);
        metadata.setTokenEndpoint(tokenEndpoint);
        metadata.setGrantTypesSupported(parseCommaSeparatedValues(grantTypesSupported));
        metadata.setResponseTypesSupported(parseCommaSeparatedValues(responseTypesSupported));
        metadata.setCodeChallengeMethodsSupported(parseCommaSeparatedValues(codeChallengeMethodsSupported));
        metadata.setInteractiveAuthorizationEndpoint(interactiveAuthorizationEndpoint);

        log.debug("OAuth Authorization Server metadata built successfully for issuer: {}", issuer);
        return metadata;
    }

    /**
     * Helper method to parse comma-separated values into a list
     * @param commaSeparatedValues the comma-separated string
     * @return List of string values
     */
    private List<String> parseCommaSeparatedValues(String commaSeparatedValues) {
        if (commaSeparatedValues == null || commaSeparatedValues.trim().isEmpty()) {
            return Arrays.asList();
        }
        return Arrays.asList(commaSeparatedValues.split(","));
    }
}
