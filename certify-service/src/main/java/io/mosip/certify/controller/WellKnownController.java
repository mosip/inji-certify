package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.OAuthASMetadataDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.services.OAuthASMetadataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/.well-known")
public class WellKnownController {

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @Autowired
    private OAuthASMetadataService oAuthASMetadataService;

    @GetMapping(value = "/openid-credential-issuer", produces = "application/json")
    public CredentialIssuerMetadataDTO getCredentialIssuerMetadata(
            @RequestParam(name = "version", required = false, defaultValue = "latest") String version) {
        return credentialConfigurationService.fetchCredentialIssuerMetadata(version);
    }

    @GetMapping(value = "/did.json")
    public Map<String, Object> getDIDDocument() {
        return vcIssuanceService.getDIDDocument();
    }

    @GetMapping(value = "/oauth-authorization-server", produces = "application/json")
    public OAuthASMetadataDTO getOAuthASMetadata() {
        return oAuthASMetadataService.getOAuthASMetadata();
    }
}

