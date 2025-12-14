package io.mosip.certify.controller;

import io.mosip.certify.core.dto.AuthorizationServerMetadata;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.services.AuthorizationServerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/.well-known")
public class WellKnownController {

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @Autowired
    private AuthorizationServerService authorizationServerService;

    @GetMapping(value = "/openid-credential-issuer", produces = "application/json")
    public CredentialIssuerMetadataDTO getCredentialIssuerMetadata(
            @RequestParam(name = "version", required = false, defaultValue = "latest") String version) {
        return credentialConfigurationService.fetchCredentialIssuerMetadata(version);
    }

    @GetMapping(value = "/oauth-authorization-server", produces = "application/json")
    public AuthorizationServerMetadata getAuthorizationServerMetadata() {
        return authorizationServerService.getInternalAuthServerMetadata();
    }

    @GetMapping(value = "/openid-configuration", produces = "application/json")
    public AuthorizationServerMetadata getOpenIDConfiguration() {
        return authorizationServerService.getInternalAuthServerMetadata();
    }

    @GetMapping(value = "/did.json")
    public Map<String, Object> getDIDDocument() {
        return vcIssuanceService.getDIDDocument();
    }
}
